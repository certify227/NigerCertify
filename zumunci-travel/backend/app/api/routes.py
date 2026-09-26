from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
import secrets

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy import func, or_
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
    FieldAgent,
    Notification,
    Payment,
    PaymentStatus,
    Rating,
    ReportReason,
    ReportStatus,
    Ride,
    RideAlert,
    RideMode,
    SafetyReport,
    TransportCompany,
    User,
    UserRole,
    VerificationStatus,
)
from app.schemas.schemas import (
    AcceptCharterIn,
    AdminUserOut,
    BookingCreate,
    BookingOut,
    BookingCompleteIn,
    CancelBookingIn,
    CityOut,
    CompanyOut,
    ContactRevealOut,
    EmergencyContactIn,
    FieldAgentOut,
    FraudOverviewOut,
    HealthOut,
    MessageOut,
    OtpSendOut,
    OtpVerifyIn,
    NotificationOut,
    PaymentConfirm,
    PaymentConfirmResult,
    PaymentOut,
    PaymentWebhookIn,
    ProductConfigOut,
    PublicProfileOut,
    PublicRatingOut,
    RatingCreate,
    RatingOut,
    ReportStatusUpdate,
    RideAlertCreate,
    RideAlertOut,
    RideCreate,
    RideModerationIn,
    RideOut,
    BookingReceiptOut,
    DriverEarningsOut,
    CompanyOverviewOut,
    AdminKpiOut,
    SafetyCharterOut,
    SafetyReportCreate,
    SafetyReportOut,
    TokenOut,
    TripShareOut,
    UssdIn,
    UssdOut,
    UserCreate,
    UserLogin,
    UserOut,
    VerificationReview,
    VerificationSubmit,
)
from app.services.payments import apply_payment_outcome, get_payment_adapter
from app.services.sms import get_sms_log, send_booking_sms, send_otp_sms
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
from app.services.ussd import handle_ussd

router = APIRouter()
settings = get_settings()


def _driver_rating_stats(db: Session, driver_id: int) -> tuple[float | None, int]:
    row = (
        db.query(func.avg(Rating.score), func.count(Rating.id))
        .filter(Rating.reviewee_id == driver_id)
        .one()
    )
    avg, count = row[0], int(row[1] or 0)
    if not count:
        return None, 0
    return round(float(avg), 1), count


def _driver_brief(driver: User, *, reveal_phone: bool, db: Session | None = None) -> dict:
    rating_avg, rating_count = (None, 0)
    if db is not None:
        rating_avg, rating_count = _driver_rating_stats(db, driver.id)
    return {
        "id": driver.id,
        "full_name": driver.full_name,
        "phone": driver.phone if reveal_phone else mask_phone(driver.phone),
        "is_verified": driver.is_verified,
        "verification_status": driver.verification_status,
        "city": driver.city,
        "contact_hidden": not reveal_phone,
        "rating_avg": rating_avg,
        "rating_count": rating_count,
    }


def serialize_ride(ride: Ride, *, reveal_phone: bool = False, db: Session | None = None) -> dict:
    company = None
    if ride.company_id and getattr(ride, "company", None) is not None:
        company = {
            "id": ride.company.id,
            "slug": ride.company.slug,
            "name": ride.company.name,
            "city_hub": ride.company.city_hub,
            "is_verified": ride.company.is_verified,
        }
    elif ride.company_id and db is not None:
        c = db.get(TransportCompany, ride.company_id)
        if c:
            company = {
                "id": c.id,
                "slug": c.slug,
                "name": c.name,
                "city_hub": c.city_hub,
                "is_verified": c.is_verified,
            }
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
        "driver": _driver_brief(ride.driver, reveal_phone=reveal_phone, db=db),
        "company": company,
    }


def serialize_booking(booking: Booking, viewer: User, db: Session | None = None) -> dict:
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
        "insurance_fee": booking.insurance_fee or 0,
        "with_insurance": bool(booking.with_insurance),
        "status": booking.status,
        "contact_unlocked": booking.contact_unlocked,
        "created_at": booking.created_at,
        "ride": serialize_ride(ride, reveal_phone=show_contact, db=db),
        "payment": booking.payment,
        "driver_phone": ride.driver.phone if show_contact else None,
        "passenger_phone": booking.passenger.phone if show_contact and booking.passenger else None,
        "passenger_name": booking.passenger.full_name if is_party and booking.passenger else None,
        "driver_whatsapp_url": whatsapp_link(ride.driver.phone, wa_msg) if show_contact else None,
    }


def expire_stale_pending_bookings(db: Session) -> int:
    """Libère les places des réservations pending non payées après TTL."""
    ttl = timedelta(minutes=max(settings.booking_pending_ttl_minutes, 1))
    cutoff = datetime.now(timezone.utc) - ttl
    stale = (
        db.query(Booking)
        .options(joinedload(Booking.payment), joinedload(Booking.ride))
        .filter(Booking.status == BookingStatus.PENDING)
        .all()
    )
    released = 0
    for booking in stale:
        created = booking.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        if created > cutoff:
            continue
        ride = booking.ride
        if ride:
            ride.seats_available = min(ride.seats_total, ride.seats_available + booking.seats)
        booking.status = BookingStatus.CANCELLED
        booking.contact_unlocked = False
        booking.cancelled_at = datetime.now(timezone.utc)
        booking.cancel_reason = "Expiration automatique — paiement non confirmé"
        if booking.payment and booking.payment.status == PaymentStatus.PENDING:
            booking.payment.status = PaymentStatus.FAILED
        released += 1
    if released:
        db.commit()
    return released


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
        service_cities=settings.all_service_cities,
        pilot_corridors=region_links,
        commission_rate=settings.commission_rate,
        currency=settings.currency,
        kyc_sla_hours=settings.kyc_sla_hours,
        cash_allowed_modes=settings.cash_allowed_mode_list,
        night_start_hour=settings.night_start_hour,
        night_end_hour=settings.night_end_hour,
        default_locale=settings.default_locale,
        payment_providers=settings.payment_provider_list,
        booking_pending_ttl_minutes=settings.booking_pending_ttl_minutes,
        insurance_fee_xof=settings.insurance_fee_xof,
        insurance_partner_name=settings.insurance_partner_name,
        ussd_service_code=settings.ussd_service_code,
        uemoa_coming_soon=settings.uemoa_coming_soon_list,
        uemoa_live_cities=settings.uemoa_live_city_list,
        uemoa_corridors_enabled=settings.uemoa_corridors_enabled,
        payment_aggregator=settings.payment_aggregator,
        sms_provider_name=settings.sms_provider_name,
        payment_webhook_enabled=True,
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
    code = (
        settings.otp_demo_code
        if settings.app_env == "development"
        else f"{secrets.randbelow(1_000_000):06d}"
    )
    user.otp_code = code
    user.otp_expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    sms = send_otp_sms(phone=user.phone, code=code)
    user.last_sms_at = datetime.now(timezone.utc)
    db.add(
        Notification(
            user_id=user.id,
            channel="sms",
            title="Code OTP",
            body=sms.body,
            booking_id=None,
        )
    )
    db.commit()
    return OtpSendOut(
        message=f"Code OTP envoyé via {sms.provider} vers {mask_phone(user.phone)}",
        demo_code=code if settings.app_env == "development" else None,
        expires_in_seconds=300,
        sms_message_id=sms.message_id,
        sms_provider=sms.provider,
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
    if payload.id_document_image:
        img = payload.id_document_image.strip()
        if len(img) > settings.kyc_image_max_chars:
            raise HTTPException(status_code=400, detail="Image KYC trop lourde — compressez la photo")
        if not (img.startswith("data:image/") or img.startswith("http")):
            raise HTTPException(status_code=400, detail="Image KYC invalide (data-URL ou URL attendue)")
        user.id_document_image = img
    user.verification_status = VerificationStatus.PENDING
    user.verification_notes = "Dossier soumis — en attente de validation ZumunciTravel"
    user.is_verified = False
    db.commit()
    db.refresh(user)
    return user


def _admin_user_out(u: User) -> dict:
    return {
        "id": u.id,
        "phone": u.phone,
        "full_name": u.full_name,
        "role": u.role,
        "city": u.city,
        "is_verified": u.is_verified,
        "verification_status": u.verification_status,
        "accepted_safety_charter": u.accepted_safety_charter,
        "phone_verified": u.phone_verified,
        "emergency_contact_name": u.emergency_contact_name,
        "emergency_contact_phone": u.emergency_contact_phone,
        "is_suspended": u.is_suspended,
        "bio": u.bio,
        "company_id": u.company_id,
        "created_at": u.created_at,
        "id_document_type": u.id_document_type,
        "id_document_number": u.id_document_number,
        "id_full_name": u.id_full_name,
        "verification_notes": u.verification_notes,
        "has_document_image": bool(u.id_document_image),
        "id_document_image": u.id_document_image,
    }


@router.get("/admin/verifications/pending", response_model=list[AdminUserOut])
def pending_verifications(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    if user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Accès admin requis")
    rows = (
        db.query(User)
        .filter(User.verification_status == VerificationStatus.PENDING)
        .order_by(User.created_at.asc())
        .all()
    )
    return [_admin_user_out(u) for u in rows]


@router.post("/admin/verifications/{user_id}/review", response_model=AdminUserOut)
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
        # Ne pas bypasser l'OTP : le téléphone doit rester à vérifier séparément.
        target.verification_notes = payload.notes or "Identité validée par ZumunciTravel"
    else:
        target.verification_status = VerificationStatus.REJECTED
        target.is_verified = False
        target.verification_notes = payload.notes or "Dossier rejeté — veuillez resoumettre"
    db.commit()
    db.refresh(target)
    return _admin_user_out(target)


@router.get("/cities", response_model=list[CityOut])
def list_cities(db: Session = Depends(get_db)) -> list[City]:
    return db.query(City).filter(City.is_active.is_(True)).order_by(City.name).all()


@router.get("/companies", response_model=list[CompanyOut])
def list_companies(db: Session = Depends(get_db)) -> list[dict]:
    rows = (
        db.query(TransportCompany)
        .filter(TransportCompany.is_active.is_(True))
        .order_by(TransportCompany.name)
        .all()
    )
    out = []
    for c in rows:
        count = db.query(Ride).filter(Ride.company_id == c.id, Ride.is_active.is_(True)).count()
        out.append(
            {
                "id": c.id,
                "slug": c.slug,
                "name": c.name,
                "city_hub": c.city_hub,
                "phone": c.phone,
                "description": c.description,
                "is_verified": c.is_verified,
                "is_active": c.is_active,
                "ride_count": count,
            }
        )
    return out


@router.get("/companies/{company_id}", response_model=CompanyOut)
def get_company(company_id: int, db: Session = Depends(get_db)) -> dict:
    c = db.get(TransportCompany, company_id)
    if not c or not c.is_active:
        raise HTTPException(status_code=404, detail="Compagnie introuvable")
    count = db.query(Ride).filter(Ride.company_id == c.id, Ride.is_active.is_(True)).count()
    return {
        "id": c.id,
        "slug": c.slug,
        "name": c.name,
        "city_hub": c.city_hub,
        "phone": c.phone,
        "description": c.description,
        "is_verified": c.is_verified,
        "is_active": c.is_active,
        "ride_count": count,
    }


@router.get("/agents", response_model=list[FieldAgentOut])
def list_field_agents(
    city: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> list[FieldAgent]:
    q = db.query(FieldAgent).filter(FieldAgent.is_active.is_(True))
    if city:
        q = q.filter(FieldAgent.city.ilike(f"%{city.strip()}%"))
    return q.order_by(FieldAgent.city, FieldAgent.full_name).all()


@router.post("/ussd", response_model=UssdOut)
def ussd_session(payload: UssdIn, db: Session = Depends(get_db)) -> dict:
    """Simulateur USSD inclusion (feature phone) — menu recherche trajets."""
    result = handle_ussd(db, text=payload.text or "", phone=payload.phone)
    return {
        **result,
        "service_code": payload.service_code or settings.ussd_service_code,
    }


@router.get("/rides", response_model=list[RideOut])
def search_rides(
    origin: str | None = Query(default=None),
    destination: str | None = Query(default=None),
    departure_date: date | None = Query(default=None),
    mode: str | None = Query(default=None),
    women_priority: bool | None = Query(default=None),
    region: str | None = Query(default=None),
    company_id: int | None = Query(default=None),
    max_price: int | None = Query(default=None, ge=500, le=200_000),
    db: Session = Depends(get_db),
    viewer: User | None = Depends(get_optional_user),
) -> list[dict]:
    expire_stale_pending_bookings(db)
    q = (
        db.query(Ride)
        .options(joinedload(Ride.driver), joinedload(Ride.company))
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
    if company_id is not None:
        q = q.filter(Ride.company_id == company_id)
    if max_price is not None:
        q = q.filter(Ride.price_per_seat <= max_price)
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
        serialize_ride(ride, reveal_phone=user_can_see_driver_phone(db, viewer, ride), db=db)
        for ride in rides
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
    return serialize_ride(ride, reveal_phone=user_can_see_driver_phone(db, viewer, ride), db=db)


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
                "Villes Niger (8 régions) ou corridors UEMOA live Niamey↔Ouagadougou/Bamako."
            ),
        )
    company_id = payload.company_id
    mode = payload.mode
    # Compte compagnie : force le rattachement partenaire
    if user.role == UserRole.COMPANY:
        if not user.company_id:
            raise HTTPException(status_code=400, detail="Compte compagnie sans partenaire lié")
        company_id = user.company_id
        if mode == RideMode.CARPOOL:
            mode = RideMode.BUS
    if company_id is not None:
        company = db.get(TransportCompany, company_id)
        if not company or not company.is_active:
            raise HTTPException(status_code=400, detail="Compagnie partenaire introuvable")
        if mode == RideMode.CARPOOL:
            raise HTTPException(
                status_code=400,
                detail="Une compagnie partenaire s'applique aux modes bus / taxi brousse",
            )
        if user.role == UserRole.COMPANY and company_id != user.company_id:
            raise HTTPException(status_code=403, detail="Vous ne pouvez publier que pour votre compagnie")
    ride = Ride(
        driver_id=user.id,
        company_id=company_id,
        origin_city=origin,
        destination_city=destination,
        departure_date=payload.departure_date,
        departure_time=payload.departure_time,
        seats_total=payload.seats_total,
        seats_available=payload.seats_total,
        price_per_seat=payload.price_per_seat,
        mode=mode,
        vehicle_info=payload.vehicle_info,
        meeting_point=payload.meeting_point,
        notes=payload.notes,
        women_priority=payload.women_priority,
    )
    db.add(ride)
    db.flush()

    # Notifier les alertes matching (SMS simulé / inbox)
    alerts = (
        db.query(RideAlert)
        .filter(
            RideAlert.is_active.is_(True),
            RideAlert.origin_city.ilike(origin),
            RideAlert.destination_city.ilike(destination),
            RideAlert.user_id != user.id,
        )
        .all()
    )
    for alert in alerts:
        if alert.max_price is not None and ride.price_per_seat > alert.max_price:
            continue
        body = (
            f"Alerte ZumunciTravel: nouveau trajet {origin}->{destination} "
            f"le {ride.departure_date} a {ride.departure_time} — {ride.price_per_seat} XOF/place."
        )
        db.add(
            Notification(
                user_id=alert.user_id,
                channel="sms",
                title="Nouveau trajet correspondant",
                body=body,
                booking_id=None,
            )
        )
        subscriber = db.get(User, alert.user_id)
        if subscriber:
            subscriber.last_sms_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(ride)
    ride = (
        db.query(Ride)
        .options(joinedload(Ride.driver), joinedload(Ride.company))
        .filter(Ride.id == ride.id)
        .one()
    )
    return serialize_ride(ride, reveal_phone=True, db=db)


@router.post("/rides/{ride_id}/book", response_model=BookingOut, status_code=status.HTTP_201_CREATED)
def book_ride(
    ride_id: int,
    payload: BookingCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    ensure_can_transact(user)
    expire_stale_pending_bookings(db)
    ride = (
        db.query(Ride)
        .options(joinedload(Ride.driver), joinedload(Ride.company))
        .filter(Ride.id == ride_id)
        .first()
    )
    if not ride or not ride.is_active:
        raise HTTPException(status_code=404, detail="Trajet introuvable")
    if ride.driver.verification_status != VerificationStatus.VERIFIED or ride.driver.is_suspended:
        raise HTTPException(status_code=400, detail="Ce convoyeur n'est pas autorisé actuellement")
    if ride.driver_id == user.id:
        raise HTTPException(status_code=400, detail="Vous ne pouvez pas réserver votre propre trajet")
    if payload.seats > ride.seats_available:
        raise HTTPException(status_code=400, detail="Pas assez de places disponibles")
    if ride.women_priority and not payload.accept_women_priority_rules:
        raise HTTPException(
            status_code=400,
            detail=(
                "Ce trajet est « priorité femmes ». "
                "Confirmez le respect des règles (ambiance professionnelle uniquement)."
            ),
        )

    assert_payment_allowed(ride.mode, payload.payment_provider.value)

    seats_total = payload.seats * ride.price_per_seat
    insurance_fee = settings.insurance_fee_xof if payload.with_insurance else 0
    total = seats_total + insurance_fee
    platform_fee, driver_amount = compute_fees(seats_total)
    payment_phone = payload.payment_phone or user.phone
    booking = Booking(
        ride_id=ride.id,
        passenger_id=user.id,
        seats=payload.seats,
        total_amount=total,
        platform_fee=platform_fee,
        driver_amount=driver_amount,
        insurance_fee=insurance_fee,
        with_insurance=payload.with_insurance,
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
        instructions=init.instructions,
        checkout_url=init.checkout_url,
        ussd_hint=init.ussd_hint,
    )
    db.add(payment)

    # SMS confirmation via provider sandbox
    sms_body = (
        f"ZumunciTravel: reservation #{booking.id} {ride.origin_city}->{ride.destination_city} "
        f"le {ride.departure_date} {ride.departure_time}. "
        f"Montant {total} XOF a confirmer"
        + (" (assurance incluse)." if payload.with_insurance else ".")
    )
    sms = send_booking_sms(phone=user.phone, body=sms_body)
    db.add(
        Notification(
            user_id=user.id,
            channel="sms",
            title="Reservation en attente",
            body=f"{sms_body} [{sms.message_id}]",
            booking_id=booking.id,
        )
    )
    user.last_sms_at = datetime.now(timezone.utc)
    db.commit()

    booking = (
        db.query(Booking)
        .options(
            joinedload(Booking.payment),
            joinedload(Booking.passenger),
            joinedload(Booking.ride).joinedload(Ride.driver),
            joinedload(Booking.ride).joinedload(Ride.company),
        )
        .filter(Booking.id == booking.id)
        .one()
    )
    return serialize_booking(booking, user, db=db)


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
    return [serialize_booking(b, user, db=db) for b in rows]


@router.get("/me/rides", response_model=list[RideOut])
def my_rides(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[dict]:
    q = db.query(Ride).options(joinedload(Ride.driver), joinedload(Ride.company))
    if user.role == UserRole.COMPANY and user.company_id:
        q = q.filter(Ride.company_id == user.company_id)
    else:
        q = q.filter(Ride.driver_id == user.id)
    rides = q.order_by(Ride.departure_date.desc()).all()
    return [serialize_ride(r, reveal_phone=True, db=db) for r in rides]


@router.get("/me/incoming-bookings", response_model=list[BookingOut])
def my_incoming_bookings(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    """Réservations reçues sur les trajets du conducteur / de la compagnie."""
    expire_stale_pending_bookings(db)
    q = (
        db.query(Booking)
        .options(
            joinedload(Booking.payment),
            joinedload(Booking.passenger),
            joinedload(Booking.ride).joinedload(Ride.driver),
            joinedload(Booking.ride).joinedload(Ride.company),
        )
        .join(Ride, Booking.ride_id == Ride.id)
    )
    if user.role == UserRole.COMPANY and user.company_id:
        q = q.filter(Ride.company_id == user.company_id)
    else:
        q = q.filter(Ride.driver_id == user.id)
    rows = q.order_by(Booking.created_at.desc()).all()
    return [serialize_booking(b, user, db=db) for b in rows]


@router.get("/me/company/overview", response_model=CompanyOverviewOut)
def company_overview(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    if user.role != UserRole.COMPANY or not user.company_id:
        raise HTTPException(status_code=403, detail="Réservé aux comptes compagnie")
    company = db.get(TransportCompany, user.company_id)
    if not company:
        raise HTTPException(status_code=404, detail="Compagnie introuvable")
    rides_total = db.query(Ride).filter(Ride.company_id == company.id).count()
    rides_active = (
        db.query(Ride).filter(Ride.company_id == company.id, Ride.is_active.is_(True)).count()
    )
    paid_statuses = [BookingStatus.PAID, BookingStatus.COMPLETED]
    bookings = (
        db.query(Booking)
        .join(Ride, Booking.ride_id == Ride.id)
        .filter(Ride.company_id == company.id)
        .all()
    )
    pending = sum(1 for b in bookings if b.status == BookingStatus.PENDING)
    paid = [b for b in bookings if b.status in paid_statuses]
    return {
        "company_id": company.id,
        "company_name": company.name,
        "rides_active": rides_active,
        "rides_total": rides_total,
        "bookings_pending": pending,
        "bookings_paid": len(paid),
        "seats_sold": sum(b.seats for b in paid),
        "gmv_xof": sum(b.total_amount for b in paid),
        "currency": settings.currency,
    }


@router.post("/payments/{payment_id}/confirm", response_model=PaymentConfirmResult)
def confirm_payment(
    payment_id: int,
    payload: PaymentConfirm,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    payment = (
        db.query(Payment)
        .options(
            joinedload(Payment.booking).joinedload(Booking.ride).joinedload(Ride.driver),
            joinedload(Payment.booking).joinedload(Booking.passenger),
        )
        .filter(Payment.id == payment_id)
        .first()
    )
    if not payment:
        raise HTTPException(status_code=404, detail="Paiement introuvable")
    booking = payment.booking
    ride = booking.ride
    is_company_ops = (
        user.role == UserRole.COMPANY
        and user.company_id
        and ride.company_id == user.company_id
    )
    if booking.passenger_id != user.id and ride.driver_id != user.id and not is_company_ops:
        raise HTTPException(status_code=403, detail="Accès refusé")

    # Idempotence : ne pas rejouer un paiement déjà tranché.
    if payment.status in {PaymentStatus.SUCCESS, PaymentStatus.REFUNDED}:
        return {
            "id": payment.id,
            "provider": payment.provider,
            "phone": payment.phone,
            "amount": payment.amount,
            "currency": payment.currency,
            "status": payment.status,
            "external_ref": payment.external_ref,
            "created_at": payment.created_at,
            "sms_preview": None,
        }
    if payment.status == PaymentStatus.FAILED and booking.status != BookingStatus.PENDING:
        raise HTTPException(status_code=400, detail="Ce paiement est déjà clôturé")
    if booking.status != BookingStatus.PENDING:
        raise HTTPException(
            status_code=400,
            detail=f"Réservation non confirmable (statut : {booking.status.value})",
        )

    sms_preview = apply_payment_outcome(
        db,
        payment=payment,
        booking=booking,
        ride=ride,
        success=payload.success,
        external_ref=payload.external_ref,
    )
    db.commit()
    db.refresh(payment)
    return {
        "id": payment.id,
        "provider": payment.provider,
        "phone": payment.phone,
        "amount": payment.amount,
        "currency": payment.currency,
        "status": payment.status,
        "external_ref": payment.external_ref,
        "created_at": payment.created_at,
        "sms_preview": sms_preview,
    }


@router.post("/payments/webhook/sandbox", response_model=PaymentConfirmResult)
def payment_webhook_sandbox(
    payload: PaymentWebhookIn,
    db: Session = Depends(get_db),
    x_zumunci_webhook_secret: str | None = Header(default=None),
) -> dict:
    """Callback sandbox agrégateur — simule PayGate/Hub2/CinetPay."""
    if x_zumunci_webhook_secret != settings.payment_webhook_secret:
        raise HTTPException(status_code=401, detail="Secret webhook invalide")
    payment = (
        db.query(Payment)
        .options(
            joinedload(Payment.booking).joinedload(Booking.ride).joinedload(Ride.driver),
            joinedload(Payment.booking).joinedload(Booking.passenger),
        )
        .filter(Payment.external_ref == payload.external_ref)
        .first()
    )
    if not payment:
        raise HTTPException(status_code=404, detail="Paiement introuvable pour cette référence")
    booking = payment.booking
    ride = booking.ride

    if payment.status in {PaymentStatus.SUCCESS, PaymentStatus.REFUNDED}:
        return {
            "id": payment.id,
            "provider": payment.provider,
            "phone": payment.phone,
            "amount": payment.amount,
            "currency": payment.currency,
            "status": payment.status,
            "external_ref": payment.external_ref,
            "created_at": payment.created_at,
            "sms_preview": None,
        }
    if booking.status != BookingStatus.PENDING:
        raise HTTPException(
            status_code=400,
            detail=f"Réservation non confirmable (statut : {booking.status.value})",
        )

    success = payload.status == "success"
    sms_preview = apply_payment_outcome(
        db,
        payment=payment,
        booking=booking,
        ride=ride,
        success=success,
        external_ref=payload.provider_ref or payment.external_ref,
    )
    db.commit()
    db.refresh(payment)
    return {
        "id": payment.id,
        "provider": payment.provider,
        "phone": payment.phone,
        "amount": payment.amount,
        "currency": payment.currency,
        "status": payment.status,
        "external_ref": payment.external_ref,
        "created_at": payment.created_at,
        "sms_preview": sms_preview,
    }


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
        booking.payment.status = PaymentStatus.REFUNDED
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
    return serialize_booking(booking, user, db=db)


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
    db.flush()
    serious = {
        ReportReason.SCAM,
        ReportReason.HARASSMENT,
        ReportReason.INAPPROPRIATE_BEHAVIOR,
        ReportReason.FAKE_PROFILE,
    }
    if payload.reason in serious and reported.role != UserRole.ADMIN:
        open_count = (
            db.query(SafetyReport)
            .filter(
                SafetyReport.reported_user_id == reported.id,
                SafetyReport.status == ReportStatus.OPEN,
                SafetyReport.reason.in_(list(serious)),
            )
            .count()
        )
        if open_count >= settings.auto_suspend_report_threshold:
            reported.is_suspended = True
            report.details = (
                report.details
                + f"\n[Auto] Compte suspendu après {open_count} signalements ouverts."
            )
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


@router.post("/bookings/{booking_id}/complete", response_model=BookingOut)
def complete_booking(
    booking_id: int,
    payload: BookingCompleteIn,
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
    if booking.status == BookingStatus.COMPLETED:
        return serialize_booking(booking, user, db=db)
    if booking.status != BookingStatus.PAID:
        raise HTTPException(status_code=400, detail="Seules les réservations payées peuvent être clôturées")
    booking.status = BookingStatus.COMPLETED
    _ = payload.note  # reserved for future audit trail
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
    return serialize_booking(booking, user, db=db)


@router.post("/bookings/{booking_id}/rate", response_model=RatingOut, status_code=status.HTTP_201_CREATED)
def rate_booking(
    booking_id: int,
    payload: RatingCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Rating:
    booking = (
        db.query(Booking)
        .options(joinedload(Booking.ride))
        .filter(Booking.id == booking_id)
        .first()
    )
    if not booking:
        raise HTTPException(status_code=404, detail="Réservation introuvable")
    ride = booking.ride
    if user.id not in {booking.passenger_id, ride.driver_id}:
        raise HTTPException(status_code=403, detail="Seul le passager ou le conducteur peut noter")
    if booking.status not in {BookingStatus.PAID, BookingStatus.COMPLETED}:
        raise HTTPException(status_code=400, detail="La réservation doit être payée")

    reviewee_id = ride.driver_id if user.id == booking.passenger_id else booking.passenger_id
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
        reviewee_id=reviewee_id,
        score=payload.score,
        comment=payload.comment,
    )
    if booking.status == BookingStatus.PAID:
        booking.status = BookingStatus.COMPLETED
    db.add(rating)
    db.commit()
    db.refresh(rating)
    return rating


@router.get("/admin/rides", response_model=list[RideOut])
def admin_list_rides(
    active_only: bool | None = Query(default=None),
    admin: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    if admin.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Accès admin requis")
    q = db.query(Ride).options(joinedload(Ride.driver))
    if active_only is True:
        q = q.filter(Ride.is_active.is_(True))
    elif active_only is False:
        q = q.filter(Ride.is_active.is_(False))
    rides = q.order_by(Ride.departure_date.desc(), Ride.id.desc()).limit(100).all()
    return [serialize_ride(r, reveal_phone=True, db=db) for r in rides]


@router.post("/admin/rides/{ride_id}/moderate", response_model=RideOut)
def admin_moderate_ride(
    ride_id: int,
    payload: RideModerationIn,
    admin: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    if admin.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Accès admin requis")
    ride = db.query(Ride).options(joinedload(Ride.driver)).filter(Ride.id == ride_id).first()
    if not ride:
        raise HTTPException(status_code=404, detail="Trajet introuvable")
    ride.is_active = payload.is_active
    if payload.notes:
        note = payload.notes.strip()
        ride.notes = f"[Modération] {note}" if not ride.notes else f"{ride.notes}\n[Modération] {note}"
    db.commit()
    db.refresh(ride)
    ride = db.query(Ride).options(joinedload(Ride.driver)).filter(Ride.id == ride_id).one()
    return serialize_ride(ride, reveal_phone=True, db=db)


@router.get("/admin/fraud/overview", response_model=FraudOverviewOut)
def admin_fraud_overview(
    admin: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    if admin.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Accès admin requis")

    since = datetime.now(timezone.utc) - timedelta(hours=24)
    suspended = db.query(User).filter(User.is_suspended.is_(True)).count()
    open_reports = db.query(SafetyReport).filter(SafetyReport.status == ReportStatus.OPEN).count()
    failed_pay = (
        db.query(Payment)
        .filter(Payment.status == PaymentStatus.FAILED, Payment.updated_at >= since)
        .count()
    )
    night = 0
    for r in db.query(Ride).filter(Ride.is_active.is_(True)).all():
        if is_night_departure(r.departure_time):
            night += 1
    pending_kyc = (
        db.query(User).filter(User.verification_status == VerificationStatus.PENDING).count()
    )
    active_alerts = db.query(RideAlert).filter(RideAlert.is_active.is_(True)).count()

    flags = []
    # Utilisateurs avec ≥2 signalements ouverts
    multi = (
        db.query(SafetyReport.reported_user_id, func.count(SafetyReport.id))
        .filter(SafetyReport.status == ReportStatus.OPEN)
        .group_by(SafetyReport.reported_user_id)
        .having(func.count(SafetyReport.id) >= 2)
        .all()
    )
    for uid, cnt in multi:
        u = db.get(User, uid)
        flags.append(
            {
                "kind": "multi_report",
                "severity": "high" if cnt >= settings.auto_suspend_report_threshold else "medium",
                "label": f"{u.full_name if u else uid} — {cnt} signalements ouverts",
                "ref_id": uid,
            }
        )
    # Paiements échoués récents groupés
    if failed_pay >= 3:
        flags.append(
            {
                "kind": "payment_failures",
                "severity": "medium",
                "label": f"{failed_pay} paiements échoués (24 h)",
                "ref_id": None,
            }
        )
    for r in db.query(Ride).filter(Ride.is_active.is_(True)).all():
        if is_night_departure(r.departure_time) and r.price_per_seat < 1500:
            flags.append(
                {
                    "kind": "suspicious_night_price",
                    "severity": "low",
                    "label": f"Trajet nuit #{r.id} prix bas ({r.price_per_seat} XOF)",
                    "ref_id": r.id,
                }
            )

    return {
        "suspended_users": suspended,
        "open_reports": open_reports,
        "failed_payments_24h": failed_pay,
        "night_rides_active": night,
        "unverified_pending": pending_kyc,
        "active_alerts": active_alerts,
        "flags": flags[:30],
        "uemoa_coming_soon": settings.uemoa_coming_soon_list,
    }


@router.get("/me/alerts", response_model=list[RideAlertOut])
def my_alerts(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[RideAlert]:
    return (
        db.query(RideAlert)
        .filter(RideAlert.user_id == user.id)
        .order_by(RideAlert.created_at.desc())
        .all()
    )


@router.post("/me/alerts", response_model=RideAlertOut, status_code=status.HTTP_201_CREATED)
def create_alert(
    payload: RideAlertCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> RideAlert:
    ensure_active(user)
    origin = payload.origin_city.strip().title()
    destination = payload.destination_city.strip().title()
    if origin.casefold() == destination.casefold():
        raise HTTPException(status_code=400, detail="Départ et arrivée doivent être différents")
    if not corridor_allowed(origin, destination):
        raise HTTPException(status_code=400, detail="Corridor hors couverture Niger actuelle")
    alert = RideAlert(
        user_id=user.id,
        origin_city=origin,
        destination_city=destination,
        max_price=payload.max_price,
        is_active=True,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


@router.delete("/me/alerts/{alert_id}", response_model=MessageOut)
def delete_alert(
    alert_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> MessageOut:
    alert = db.get(RideAlert, alert_id)
    if not alert or alert.user_id != user.id:
        raise HTTPException(status_code=404, detail="Alerte introuvable")
    alert.is_active = False
    db.commit()
    return MessageOut(message="Alerte désactivée")


@router.get("/bookings/{booking_id}/receipt", response_model=BookingReceiptOut)
def booking_receipt(
    booking_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    booking = (
        db.query(Booking)
        .options(
            joinedload(Booking.payment),
            joinedload(Booking.passenger),
            joinedload(Booking.ride).joinedload(Ride.driver),
            joinedload(Booking.ride).joinedload(Ride.company),
        )
        .filter(Booking.id == booking_id)
        .first()
    )
    if not booking:
        raise HTTPException(status_code=404, detail="Réservation introuvable")
    ride = booking.ride
    if user.id not in {booking.passenger_id, ride.driver_id} and user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Accès refusé")
    paid = booking.status in {BookingStatus.PAID, BookingStatus.COMPLETED}
    company = ride.company.name if getattr(ride, "company", None) else "Indépendant"
    lines = [
        "=== RECU ZumunciTravel ===",
        f"Reservation #{booking.id}",
        f"Statut: {booking.status.value}",
        f"Trajet: {ride.origin_city} -> {ride.destination_city}",
        f"Depart: {ride.departure_date} {ride.departure_time}",
        f"Mode: {ride.mode.value} · {company}",
        f"Places: {booking.seats}",
        f"Passager: {booking.passenger.full_name if booking.passenger else '—'}",
        f"Convoyeur: {ride.driver.full_name}",
        f"Sous-total places: {booking.total_amount - (booking.insurance_fee or 0)} {settings.currency}",
        f"Assurance: {booking.insurance_fee or 0} {settings.currency}",
        f"Commission plateforme: {booking.platform_fee} {settings.currency}",
        f"Reversement convoyeur: {booking.driver_amount} {settings.currency}",
        f"TOTAL: {booking.total_amount} {settings.currency}",
    ]
    if booking.payment:
        lines.append(
            f"Paiement: {booking.payment.provider.value} · {booking.payment.status.value}"
            + (f" · ref {booking.payment.external_ref}" if booking.payment.external_ref else "")
        )
    lines.append("Merci de voyager en confiance.")
    return {
        "booking_id": booking.id,
        "status": booking.status,
        "title": f"Reçu #{booking.id} — {ride.origin_city} → {ride.destination_city}",
        "receipt_text": "\n".join(lines),
        "total_amount": booking.total_amount,
        "currency": settings.currency,
        "insurance_fee": booking.insurance_fee or 0,
        "platform_fee": booking.platform_fee,
        "driver_amount": booking.driver_amount,
        "paid": paid,
    }


@router.get("/me/earnings", response_model=DriverEarningsOut)
def my_earnings(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict:
    paid_statuses = [BookingStatus.PAID, BookingStatus.COMPLETED]
    if user.role == UserRole.COMPANY and user.company_id:
        rides_published = db.query(Ride).filter(Ride.company_id == user.company_id).count()
        rows = (
            db.query(Booking)
            .join(Ride, Booking.ride_id == Ride.id)
            .filter(Ride.company_id == user.company_id, Booking.status.in_(paid_statuses))
            .all()
        )
    else:
        rides_published = db.query(Ride).filter(Ride.driver_id == user.id).count()
        rows = (
            db.query(Booking)
            .join(Ride, Booking.ride_id == Ride.id)
            .filter(Ride.driver_id == user.id, Booking.status.in_(paid_statuses))
            .all()
        )
    gross = sum(b.driver_amount for b in rows)
    seats = sum(b.seats for b in rows)
    completed = sum(1 for b in rows if b.status == BookingStatus.COMPLETED)
    return {
        "rides_published": rides_published,
        "bookings_paid": len(rows),
        "bookings_completed": completed,
        "gross_driver_amount": gross,
        "seats_sold": seats,
        "currency": settings.currency,
    }


@router.get("/admin/kpi", response_model=AdminKpiOut)
def admin_kpi(
    admin: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    if admin.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Accès admin requis")
    users_total = db.query(User).count()
    drivers_verified = (
        db.query(User)
        .filter(
            User.verification_status == VerificationStatus.VERIFIED,
            User.role.in_([UserRole.DRIVER, UserRole.BOTH, UserRole.ADMIN]),
        )
        .count()
    )
    rides_active = db.query(Ride).filter(Ride.is_active.is_(True)).count()
    bookings_total = db.query(Booking).count()
    paid = (
        db.query(Booking)
        .filter(Booking.status.in_([BookingStatus.PAID, BookingStatus.COMPLETED]))
        .all()
    )
    bookings_paid = len(paid)
    bookings_completed = sum(1 for b in paid if b.status == BookingStatus.COMPLETED)
    gmv = sum(b.total_amount for b in paid)
    fees = sum(b.platform_fee for b in paid)
    conversion = round((bookings_paid / bookings_total), 3) if bookings_total else 0.0
    open_reports = db.query(SafetyReport).filter(SafetyReport.status == ReportStatus.OPEN).count()
    return {
        "users_total": users_total,
        "drivers_verified": drivers_verified,
        "rides_active": rides_active,
        "bookings_total": bookings_total,
        "bookings_paid": bookings_paid,
        "bookings_completed": bookings_completed,
        "gmv_xof": gmv,
        "platform_fees_xof": fees,
        "conversion_rate": conversion,
        "open_reports": open_reports,
        "currency": settings.currency,
    }


@router.get("/admin/sms/log")
def admin_sms_log(admin: User = Depends(get_current_user)) -> list[dict]:
    if admin.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Accès admin requis")
    return [
        {
            "message_id": s.message_id,
            "to": s.to,
            "body": s.body,
            "provider": s.provider,
            "sandbox": s.sandbox,
            "sent_at": s.sent_at,
        }
        for s in get_sms_log(30)
    ]


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



@router.get("/users/{user_id}/public", response_model=PublicProfileOut)
def public_profile(user_id: int, db: Session = Depends(get_db)) -> dict:
    target = db.get(User, user_id)
    if not target or target.is_suspended:
        raise HTTPException(status_code=404, detail="Profil introuvable")
    avg, count = _driver_rating_stats(db, target.id)
    ratings = (
        db.query(Rating)
        .filter(Rating.reviewee_id == target.id)
        .order_by(Rating.created_at.desc())
        .limit(10)
        .all()
    )
    return {
        "id": target.id,
        "full_name": target.full_name,
        "city": target.city,
        "is_verified": target.is_verified,
        "role": target.role,
        "bio": target.bio,
        "rating_avg": avg,
        "rating_count": count,
        "ratings": [
            {"score": r.score, "comment": r.comment, "created_at": r.created_at} for r in ratings
        ],
    }


@router.get("/me/notifications", response_model=list[NotificationOut])
def my_notifications(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[Notification]:
    return (
        db.query(Notification)
        .filter(Notification.user_id == user.id)
        .order_by(Notification.created_at.desc())
        .limit(50)
        .all()
    )


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