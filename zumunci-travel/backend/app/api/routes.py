from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
import secrets

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_
from sqlalchemy.orm import Session, joinedload

from app import __version__
from app.api.deps import get_current_user, get_optional_user
from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import create_access_token, hash_password, verify_password
from app.models.entities import (
    Booking,
    BookingStatus,
    City,
    Payment,
    PaymentStatus,
    Rating,
    ReportStatus,
    Ride,
    SafetyReport,
    User,
    UserRole,
    VerificationStatus,
)
from app.schemas.schemas import (
    AcceptCharterIn,
    BookingCreate,
    BookingOut,
    CancelBookingIn,
    CityOut,
    ContactRevealOut,
    EmergencyContactIn,
    HealthOut,
    MessageOut,
    OtpSendOut,
    OtpVerifyIn,
    PaymentConfirm,
    PaymentOut,
    ProductConfigOut,
    RatingCreate,
    RatingOut,
    ReportStatusUpdate,
    RideCreate,
    RideOut,
    SafetyCharterOut,
    SafetyReportCreate,
    SafetyReportOut,
    TokenOut,
    TripShareOut,
    UserCreate,
    UserLogin,
    UserOut,
    VerificationReview,
    VerificationSubmit,
)
from app.services.payments import get_payment_adapter
from app.services.safety import (
    SAFETY_CHARTER,
    assert_payment_allowed,
    compute_fees,
    contact_may_be_revealed,
    corridor_allowed,
    ensure_active,
    ensure_can_transact,
    is_night_departure,
    mask_phone,
    whatsapp_link,
)

router = APIRouter()
settings = get_settings()


def _driver_brief(driver: User, *, reveal_phone: bool) -> dict:
    return {
        "id": driver.id,
        "full_name": driver.full_name,
        "phone": driver.phone if reveal_phone else mask_phone(driver.phone),
        "is_verified": driver.is_verified,
        "verification_status": driver.verification_status,
        "city": driver.city,
        "contact_hidden": not reveal_phone,
    }


def serialize_ride(ride: Ride, *, reveal_phone: bool = False) -> dict:
    return {
        "id": ride.id,
        "origin_city": ride.origin_city,
        "destination_city": ride.destination_city,
        "departure_date": ride.departure_date,
        "departure_time": ride.departure_time,
        "seats_total": ride.seats_total,
        "seats_available": ride.seats_available,
        "price_per_seat": ride.price_per_seat,
        "currency": settings.currency,
        "mode": ride.mode,
        "vehicle_info": ride.vehicle_info,
        "meeting_point": ride.meeting_point,
        "notes": ride.notes,
        "women_priority": ride.women_priority,
        "night_departure": is_night_departure(ride.departure_time),
        "is_active": ride.is_active,
        "driver": _driver_brief(ride.driver, reveal_phone=reveal_phone),
    }


def serialize_booking(booking: Booking, viewer: User) -> dict:
    ride = booking.ride
    reveal = contact_may_be_revealed(booking.status, booking.contact_unlocked)
    is_party = viewer.id in {booking.passenger_id, ride.driver_id}
    show_contact = reveal and is_party
    wa_msg = (
        f"Bonjour, réservation ZumunciTravel #{booking.id} "
        f"{ride.origin_city} → {ride.destination_city} le {ride.departure_date}."
    )
    return {
        "id": booking.id,
        "ride_id": booking.ride_id,
        "seats": booking.seats,
        "total_amount": booking.total_amount,
        "platform_fee": booking.platform_fee,
        "driver_amount": booking.driver_amount,
        "status": booking.status,
        "contact_unlocked": booking.contact_unlocked,
        "created_at": booking.created_at,
        "ride": serialize_ride(ride, reveal_phone=show_contact),
        "payment": booking.payment,
        "driver_phone": ride.driver.phone if show_contact else None,
        "passenger_phone": booking.passenger.phone if show_contact and booking.passenger else None,
        "driver_whatsapp_url": whatsapp_link(ride.driver.phone, wa_msg) if show_contact else None,
    }


def user_can_see_driver_phone(db: Session, viewer: User | None, ride: Ride) -> bool:
    if viewer is None:
        return False
    if viewer.id == ride.driver_id:
        return True
    booking = (
        db.query(Booking)
        .filter(
            Booking.ride_id == ride.id,
            Booking.passenger_id == viewer.id,
            Booking.contact_unlocked.is_(True),
            Booking.status.in_([BookingStatus.PAID, BookingStatus.COMPLETED]),
        )
        .first()
    )
    return booking is not None


@router.get("/health", response_model=HealthOut)
def health() -> HealthOut:
    return HealthOut(
        status="ok",
        app=settings.app_name,
        country=settings.default_country,
        currency=settings.currency,
        version=__version__,
    )


@router.get("/product/config", response_model=ProductConfigOut)
def product_config() -> ProductConfigOut:
    # Affiche les liaisons inter-régions (chefs-lieux), pas toutes les permutations secondaires
    region_links = [f"{a} → {b}" for a, b in settings.pilot_corridor_pairs]
    return ProductConfigOut(
        app=settings.app_name,
        pilot_mode=settings.pilot_mode,
        pilot_hub=settings.pilot_hub,
        national_coverage=settings.national_coverage,
        regions=settings.region_list,
        service_cities=settings.service_city_list,
        pilot_corridors=region_links,
        commission_rate=settings.commission_rate,
        currency=settings.currency,
        kyc_sla_hours=settings.kyc_sla_hours,
        cash_allowed_modes=settings.cash_allowed_mode_list,
        night_start_hour=settings.night_start_hour,
        night_end_hour=settings.night_end_hour,
        default_locale=settings.default_locale,
        payment_providers=settings.payment_provider_list,
    )


@router.get("/safety/charter", response_model=SafetyCharterOut)
def safety_charter() -> SafetyCharterOut:
    return SafetyCharterOut(**SAFETY_CHARTER)


@router.post("/auth/register", response_model=TokenOut, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, db: Session = Depends(get_db)) -> TokenOut:
    if db.query(User).filter(User.phone == payload.phone).first():
        raise HTTPException(status_code=400, detail="Ce numéro est déjà inscrit")
    now = datetime.now(timezone.utc) if payload.accept_safety_charter else None
    user = User(
        phone=payload.phone,
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
        role=payload.role,
        city=payload.city,
        accepted_safety_charter=payload.accept_safety_charter,
        safety_charter_accepted_at=now,
        verification_status=VerificationStatus.UNVERIFIED,
        is_verified=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return TokenOut(access_token=create_access_token(user.id))


@router.post("/auth/login", response_model=TokenOut)
def login(payload: UserLogin, db: Session = Depends(get_db)) -> TokenOut:
    phone = UserCreate.normalize_phone(payload.phone)
    user = db.query(User).filter(User.phone == phone).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Téléphone ou mot de passe incorrect")
    ensure_active(user)
    return TokenOut(access_token=create_access_token(user.id))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> User:
    return user


@router.post("/me/accept-charter", response_model=UserOut)
def accept_charter(
    payload: AcceptCharterIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> User:
    ensure_active(user)
    if not payload.accept:
        raise HTTPException(status_code=400, detail="La charte doit être acceptée")
    user.accepted_safety_charter = True
    user.safety_charter_accepted_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)
    return user


@router.post("/me/otp/send", response_model=OtpSendOut)
def send_otp(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> OtpSendOut:
    ensure_active(user)
    if user.phone_verified:
        return OtpSendOut(message="Numéro déjà vérifié", demo_code=None, expires_in_seconds=0)
    # MVP: OTP démo fixe en development pour tests Windows / QA
    code = "123456" if settings.app_env == "development" else f"{secrets.randbelow(1_000_000):06d}"
    user.otp_code = code
    user.otp_expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    db.commit()
    return OtpSendOut(
        message=f"Code OTP envoyé (simulé) vers {mask_phone(user.phone)}",
        demo_code=code if settings.app_env == "development" else None,
        expires_in_seconds=300,
    )


@router.post("/me/otp/verify", response_model=UserOut)
def verify_otp(
    payload: OtpVerifyIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> User:
    ensure_active(user)
    if user.phone_verified:
        return user
    if not user.otp_code or not user.otp_expires_at:
        raise HTTPException(status_code=400, detail="Aucun OTP en cours — renvoyez un code")
    expires = user.otp_expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expires:
        raise HTTPException(status_code=400, detail="OTP expiré — renvoyez un code")
    if payload.code.strip() != user.otp_code:
        raise HTTPException(status_code=400, detail="Code OTP incorrect")
    user.phone_verified = True
    user.otp_code = None
    user.otp_expires_at = None
    db.commit()
    db.refresh(user)
    return user


@router.put("/me/emergency-contact", response_model=UserOut)
def set_emergency_contact(
    payload: EmergencyContactIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> User:
    ensure_active(user)
    phone = UserCreate.normalize_phone(payload.phone)
    user.emergency_contact_name = payload.name.strip()
    user.emergency_contact_phone = phone
    db.commit()
    db.refresh(user)
    return user


@router.post("/me/verification", response_model=UserOut)
def submit_verification(
    payload: VerificationSubmit,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> User:
    ensure_active(user)
    if not payload.accept_safety_charter and not user.accepted_safety_charter:
        raise HTTPException(status_code=400, detail="Acceptez la charte de sécurité pour continuer")
    if user.verification_status == VerificationStatus.VERIFIED:
        raise HTTPException(status_code=400, detail="Compte déjà vérifié")

    user.accepted_safety_charter = True
    user.safety_charter_accepted_at = user.safety_charter_accepted_at or datetime.now(timezone.utc)
    user.id_document_type = payload.id_document_type
    user.id_document_number = payload.id_document_number.strip().upper()
    user.id_full_name = payload.id_full_name.strip()
    user.verification_status = VerificationStatus.PENDING
    user.verification_notes = "Dossier soumis — en attente de validation ZumunciTravel"
    user.is_verified = False
    db.commit()
    db.refresh(user)
    return user


@router.get("/admin/verifications/pending", response_model=list[UserOut])
def pending_verifications(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[User]:
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Accès admin requis")
    return (
        db.query(User)
        .filter(User.verification_status == VerificationStatus.PENDING)
        .order_by(User.created_at.asc())
        .all()
    )


@router.post("/admin/verifications/{user_id}/review", response_model=UserOut)
def review_verification(
    user_id: int,
    payload: VerificationReview,
    admin: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> User:
    if admin.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Accès admin requis")
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    if target.verification_status != VerificationStatus.PENDING:
        raise HTTPException(status_code=400, detail="Aucune demande en attente pour cet utilisateur")

    if payload.approve:
        target.verification_status = VerificationStatus.VERIFIED
        target.is_verified = True
        target.phone_verified = True
        target.verification_notes = payload.notes or "Identité validée par ZumunciTravel"
    else:
        target.verification_status = VerificationStatus.REJECTED
        target.is_verified = False
        target.verification_notes = payload.notes or "Dossier rejeté — veuillez resoumettre"
    db.commit()
    db.refresh(target)
    return target


@router.get("/cities", response_model=list[CityOut])
def list_cities(db: Session = Depends(get_db)) -> list[City]:
    return db.query(City).filter(City.is_active.is_(True)).order_by(City.name).all()


@router.get("/rides", response_model=list[RideOut])
def search_rides(
    origin: str | None = Query(default=None),
    destination: str | None = Query(default=None),
    departure_date: date | None = Query(default=None),
    mode: str | None = Query(default=None),
    women_priority: bool | None = Query(default=None),
    region: str | None = Query(default=None),
    db: Session = Depends(get_db),
    viewer: User | None = Depends(get_optional_user),
) -> list[dict]:
    q = (
        db.query(Ride)
        .options(joinedload(Ride.driver))
        .filter(Ride.is_active.is_(True), Ride.seats_available > 0)
        .join(User, Ride.driver_id == User.id)
        .filter(
            User.is_suspended.is_(False),
            User.verification_status == VerificationStatus.VERIFIED,
        )
    )
    if origin:
        q = q.filter(Ride.origin_city.ilike(f"%{origin.strip()}%"))
    if destination:
        q = q.filter(Ride.destination_city.ilike(f"%{destination.strip()}%"))
    if departure_date:
        q = q.filter(Ride.departure_date == departure_date)
    if mode:
        q = q.filter(Ride.mode == mode)
    if women_priority is True:
        q = q.filter(Ride.women_priority.is_(True))
    rides = q.order_by(Ride.departure_date, Ride.departure_time).all()
    if settings.national_coverage or settings.pilot_mode:
        rides = [r for r in rides if corridor_allowed(r.origin_city, r.destination_city)]
    if region:
        region_cf = region.strip().casefold()
        city_names = {
            c.name
            for c in db.query(City).filter(City.region.ilike(f"%{region.strip()}%")).all()
        }
        city_cf = {n.casefold() for n in city_names} | {region_cf}
        rides = [
            r
            for r in rides
            if r.origin_city.casefold() in city_cf or r.destination_city.casefold() in city_cf
        ]
    return [
        serialize_ride(ride, reveal_phone=user_can_see_driver_phone(db, viewer, ride)) for ride in rides
    ]


@router.get("/rides/{ride_id}", response_model=RideOut)
def get_ride(
    ride_id: int,
    db: Session = Depends(get_db),
    viewer: User | None = Depends(get_optional_user),
) -> dict:
    ride = (
        db.query(Ride)
        .options(joinedload(Ride.driver))
        .filter(Ride.id == ride_id)
        .first()
    )
    if not ride:
        raise HTTPException(status_code=404, detail="Trajet introuvable")
    return serialize_ride(ride, reveal_phone=user_can_see_driver_phone(db, viewer, ride))


@router.post("/rides", response_model=RideOut, status_code=status.HTTP_201_CREATED)
def publish_ride(
    payload: RideCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    ensure_can_transact(user)
    origin = payload.origin_city.strip().title()
    destination = payload.destination_city.strip().title()
    if origin.casefold() == destination.casefold():
        raise HTTPException(status_code=400, detail="Départ et arrivée doivent être différents")
    if not corridor_allowed(origin, destination):
        raise HTTPException(
            status_code=400,
            detail=(
                "Trajet hors couverture ZumunciTravel. "
                "Choisissez des villes desservies dans les 8 régions du Niger."
            ),
        )
    ride = Ride(
        driver_id=user.id,
        origin_city=origin,
        destination_city=destination,
        departure_date=payload.departure_date,
        departure_time=payload.departure_time,
        seats_total=payload.seats_total,
        seats_available=payload.seats_total,
        price_per_seat=payload.price_per_seat,
        mode=payload.mode,
        vehicle_info=payload.vehicle_info,
        meeting_point=payload.meeting_point,
        notes=payload.notes,
        women_priority=payload.women_priority,
    )
    db.add(ride)
    db.commit()
    db.refresh(ride)
    ride = (
        db.query(Ride)
        .options(joinedload(Ride.driver))
        .filter(Ride.id == ride.id)
        .one()
    )
    return serialize_ride(ride, reveal_phone=True)


@router.post("/rides/{ride_id}/book", response_model=BookingOut, status_code=status.HTTP_201_CREATED)
def book_ride(
    ride_id: int,
    payload: BookingCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    ensure_can_transact(user)
    ride = db.query(Ride).options(joinedload(Ride.driver)).filter(Ride.id == ride_id).first()
    if not ride or not ride.is_active:
        raise HTTPException(status_code=404, detail="Trajet introuvable")
    if ride.driver.verification_status != VerificationStatus.VERIFIED or ride.driver.is_suspended:
        raise HTTPException(status_code=400, detail="Ce convoyeur n'est pas autorisé actuellement")
    if ride.driver_id == user.id:
        raise HTTPException(status_code=400, detail="Vous ne pouvez pas réserver votre propre trajet")
    if payload.seats > ride.seats_available:
        raise HTTPException(status_code=400, detail="Pas assez de places disponibles")

    assert_payment_allowed(ride.mode, payload.payment_provider.value)

    total = payload.seats * ride.price_per_seat
    platform_fee, driver_amount = compute_fees(total)
    payment_phone = payload.payment_phone or user.phone
    booking = Booking(
        ride_id=ride.id,
        passenger_id=user.id,
        seats=payload.seats,
        total_amount=total,
        platform_fee=platform_fee,
        driver_amount=driver_amount,
        status=BookingStatus.PENDING,
        contact_unlocked=False,
    )
    db.add(booking)
    ride.seats_available -= payload.seats
    db.flush()

    adapter = get_payment_adapter(payload.payment_provider)
    init = adapter.initiate(amount=total, phone=payment_phone, booking_id=booking.id)
    payment = Payment(
        booking_id=booking.id,
        provider=payload.payment_provider,
        phone=payment_phone,
        amount=total,
        currency=settings.currency,
        status=PaymentStatus.PENDING,
        external_ref=init.external_ref,
    )
    db.add(payment)
    db.commit()

    booking = (
        db.query(Booking)
        .options(
            joinedload(Booking.payment),
            joinedload(Booking.passenger),
            joinedload(Booking.ride).joinedload(Ride.driver),
        )
        .filter(Booking.id == booking.id)
        .one()
    )
    return serialize_booking(booking, user)


@router.get("/me/bookings", response_model=list[BookingOut])
def my_bookings(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    rows = (
        db.query(Booking)
        .options(
            joinedload(Booking.payment),
            joinedload(Booking.passenger),
            joinedload(Booking.ride).joinedload(Ride.driver),
        )
        .filter(Booking.passenger_id == user.id)
        .order_by(Booking.created_at.desc())
        .all()
    )
    return [serialize_booking(b, user) for b in rows]


@router.get("/me/rides", response_model=list[RideOut])
def my_rides(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    rides = (
        db.query(Ride)
        .options(joinedload(Ride.driver))
        .filter(Ride.driver_id == user.id)
        .order_by(Ride.departure_date.desc())
        .all()
    )
    return [serialize_ride(r, reveal_phone=True) for r in rides]


@router.post("/payments/{payment_id}/confirm", response_model=PaymentOut)
def confirm_payment(
    payment_id: int,
    payload: PaymentConfirm,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Payment:
    payment = (
        db.query(Payment)
        .options(joinedload(Payment.booking).joinedload(Booking.ride))
        .filter(Payment.id == payment_id)
        .first()
    )
    if not payment:
        raise HTTPException(status_code=404, detail="Paiement introuvable")
    booking = payment.booking
    ride = booking.ride
    if booking.passenger_id != user.id and ride.driver_id != user.id:
        raise HTTPException(status_code=403, detail="Accès refusé")

    if payload.success:
        payment.status = PaymentStatus.SUCCESS
        booking.status = BookingStatus.PAID
        booking.contact_unlocked = True
        if payload.external_ref:
            payment.external_ref = payload.external_ref
    else:
        payment.status = PaymentStatus.FAILED
        if booking.status == BookingStatus.PENDING:
            ride.seats_available += booking.seats
            booking.status = BookingStatus.CANCELLED
            booking.contact_unlocked = False
    db.commit()
    db.refresh(payment)
    return payment


@router.get("/bookings/{booking_id}/contact", response_model=ContactRevealOut)
def reveal_contact(
    booking_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ContactRevealOut:
    booking = (
        db.query(Booking)
        .options(
            joinedload(Booking.passenger),
            joinedload(Booking.ride).joinedload(Ride.driver),
        )
        .filter(Booking.id == booking_id)
        .first()
    )
    if not booking:
        raise HTTPException(status_code=404, detail="Réservation introuvable")
    if user.id not in {booking.passenger_id, booking.ride.driver_id}:
        raise HTTPException(status_code=403, detail="Accès refusé")

    if not contact_may_be_revealed(booking.status, booking.contact_unlocked):
        return ContactRevealOut(
            booking_id=booking.id,
            contact_unlocked=False,
            warning=(
                "Contact masqué. Finalisez le paiement Mobile Money sur ZumunciTravel "
                "pour débloquer la mise en relation. Aucun échange hors plateforme avant cela."
            ),
        )

    ride = booking.ride
    wa_msg = (
        f"Bonjour, réservation ZumunciTravel #{booking.id} "
        f"{ride.origin_city} → {ride.destination_city} le {ride.departure_date}."
    )
    return ContactRevealOut(
        booking_id=booking.id,
        contact_unlocked=True,
        driver_name=ride.driver.full_name,
        driver_phone=ride.driver.phone,
        passenger_name=booking.passenger.full_name,
        passenger_phone=booking.passenger.phone,
        driver_whatsapp_url=whatsapp_link(ride.driver.phone, wa_msg),
        passenger_whatsapp_url=whatsapp_link(booking.passenger.phone, wa_msg),
        warning=(
            "Contact débloqué uniquement pour ce trajet (appel ou WhatsApp). "
            "Usage transport uniquement — signalez tout comportement déplacé ou arnaque."
        ),
    )


@router.post("/bookings/{booking_id}/cancel", response_model=BookingOut)
def cancel_booking(
    booking_id: int,
    payload: CancelBookingIn,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    booking = (
        db.query(Booking)
        .options(
            joinedload(Booking.payment),
            joinedload(Booking.passenger),
            joinedload(Booking.ride).joinedload(Ride.driver),
        )
        .filter(Booking.id == booking_id)
        .first()
    )
    if not booking:
        raise HTTPException(status_code=404, detail="Réservation introuvable")
    ride = booking.ride
    if user.id not in {booking.passenger_id, ride.driver_id}:
        raise HTTPException(status_code=403, detail="Accès refusé")
    if booking.status in {BookingStatus.CANCELLED, BookingStatus.COMPLETED}:
        raise HTTPException(status_code=400, detail="Cette réservation ne peut plus être annulée")
    # Règle V1 : annulation libre avant le jour du départ
    if ride.departure_date < date.today():
        raise HTTPException(status_code=400, detail="Trajet déjà passé — annulation impossible")
    if ride.departure_date == date.today():
        raise HTTPException(
            status_code=400,
            detail="Annulation le jour du départ non autorisée en V1 — contactez le support",
        )

    if booking.status in {BookingStatus.PENDING, BookingStatus.PAID}:
        ride.seats_available = min(ride.seats_total, ride.seats_available + booking.seats)
    booking.status = BookingStatus.CANCELLED
    booking.contact_unlocked = False
    booking.cancelled_at = datetime.now(timezone.utc)
    booking.cancel_reason = (payload.reason or "Annulation utilisateur").strip()
    if booking.payment and booking.payment.status == PaymentStatus.SUCCESS:
        booking.payment.status = PaymentStatus.FAILED  # marque remboursement à traiter (MVP)
    db.commit()
    db.refresh(booking)
    booking = (
        db.query(Booking)
        .options(
            joinedload(Booking.payment),
            joinedload(Booking.passenger),
            joinedload(Booking.ride).joinedload(Ride.driver),
        )
        .filter(Booking.id == booking_id)
        .one()
    )
    return serialize_booking(booking, user)


@router.get("/bookings/{booking_id}/share", response_model=TripShareOut)
def share_trip(
    booking_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> TripShareOut:
    booking = (
        db.query(Booking)
        .options(
            joinedload(Booking.passenger),
            joinedload(Booking.ride).joinedload(Ride.driver),
        )
        .filter(Booking.id == booking_id)
        .first()
    )
    if not booking:
        raise HTTPException(status_code=404, detail="Réservation introuvable")
    if booking.passenger_id != user.id:
        raise HTTPException(status_code=403, detail="Seul le passager peut partager son trajet")
    if booking.status not in {BookingStatus.PAID, BookingStatus.COMPLETED}:
        raise HTTPException(status_code=400, detail="Partage disponible après paiement")

    ride = booking.ride
    driver_phone = ride.driver.phone if booking.contact_unlocked else "masqué"
    share_text = (
        f"ZumunciTravel — je voyage le {ride.departure_date} à {ride.departure_time} "
        f"de {ride.origin_city} vers {ride.destination_city}. "
        f"Convoyeur : {ride.driver.full_name} ({driver_phone}). "
        f"Réservation #{booking.id}. En cas de souci, contactez-moi."
    )
    emergency_url = None
    if user.emergency_contact_phone:
        emergency_url = whatsapp_link(user.emergency_contact_phone, share_text)
    return TripShareOut(
        booking_id=booking.id,
        share_text=share_text,
        emergency_whatsapp_url=emergency_url,
    )


@router.post("/safety/reports", response_model=SafetyReportOut, status_code=status.HTTP_201_CREATED)
def create_report(
    payload: SafetyReportCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> SafetyReport:
    ensure_active(user)
    if payload.reported_user_id == user.id:
        raise HTTPException(status_code=400, detail="Vous ne pouvez pas vous signaler vous-même")
    reported = db.get(User, payload.reported_user_id)
    if not reported:
        raise HTTPException(status_code=404, detail="Utilisateur signalé introuvable")
    if payload.booking_id:
        booking = db.get(Booking, payload.booking_id)
        if not booking:
            raise HTTPException(status_code=404, detail="Réservation introuvable")

    report = SafetyReport(
        reporter_id=user.id,
        reported_user_id=payload.reported_user_id,
        booking_id=payload.booking_id,
        reason=payload.reason,
        details=payload.details.strip(),
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


@router.get("/admin/reports", response_model=list[SafetyReportOut])
def list_reports(
    admin: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[SafetyReport]:
    if admin.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Accès admin requis")
    return db.query(SafetyReport).order_by(SafetyReport.created_at.desc()).limit(100).all()


@router.post("/admin/reports/{report_id}/review", response_model=SafetyReportOut)
def review_report(
    report_id: int,
    payload: ReportStatusUpdate,
    admin: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> SafetyReport:
    if admin.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Accès admin requis")
    report = db.get(SafetyReport, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Signalement introuvable")
    report.status = payload.status
    if payload.suspend_user:
        target = db.get(User, report.reported_user_id)
        if target and target.role != UserRole.ADMIN:
            target.is_suspended = True
    db.commit()
    db.refresh(report)
    return report


@router.post("/bookings/{booking_id}/rate", response_model=RatingOut, status_code=status.HTTP_201_CREATED)
def rate_booking(
    booking_id: int,
    payload: RatingCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Rating:
    booking = db.query(Booking).filter(Booking.id == booking_id).first()
    if not booking:
        raise HTTPException(status_code=404, detail="Réservation introuvable")
    if booking.passenger_id != user.id:
        raise HTTPException(status_code=403, detail="Seul le passager peut noter pour l'instant")
    if booking.status not in {BookingStatus.PAID, BookingStatus.COMPLETED}:
        raise HTTPException(status_code=400, detail="La réservation doit être payée")

    ride = db.get(Ride, booking.ride_id)
    assert ride is not None
    existing = (
        db.query(Rating)
        .filter(Rating.booking_id == booking_id, Rating.reviewer_id == user.id)
        .first()
    )
    if existing:
        raise HTTPException(status_code=400, detail="Vous avez déjà noté ce trajet")

    rating = Rating(
        booking_id=booking.id,
        reviewer_id=user.id,
        reviewee_id=ride.driver_id,
        score=payload.score,
        comment=payload.comment,
    )
    booking.status = BookingStatus.COMPLETED
    db.add(rating)
    db.commit()
    db.refresh(rating)
    return rating


@router.get("/payments/providers", response_model=list[str])
def payment_providers() -> list[str]:
    return settings.payment_provider_list


@router.get("/search/suggest", response_model=list[str])
def suggest_cities(q: str = Query(min_length=1), db: Session = Depends(get_db)) -> list[str]:
    rows = (
        db.query(City.name)
        .filter(or_(City.name.ilike(f"%{q}%"), City.region.ilike(f"%{q}%")))
        .order_by(City.name)
        .limit(8)
        .all()
    )
    return [r[0] for r in rows]


@router.delete("/rides/{ride_id}", response_model=MessageOut)
def deactivate_ride(
    ride_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> MessageOut:
    ride = db.get(Ride, ride_id)
    if not ride:
        raise HTTPException(status_code=404, detail="Trajet introuvable")
    if ride.driver_id != user.id:
        raise HTTPException(status_code=403, detail="Accès refusé")
    ride.is_active = False
    db.commit()
    return MessageOut(message="Trajet désactivé")