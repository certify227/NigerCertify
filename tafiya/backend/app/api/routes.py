from __future__ import annotations

from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_
from sqlalchemy.orm import Session, joinedload

from app import __version__
from app.api.deps import get_current_user
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
    Ride,
    User,
)
from app.schemas.schemas import (
    BookingCreate,
    BookingOut,
    CityOut,
    HealthOut,
    MessageOut,
    PaymentConfirm,
    PaymentOut,
    RatingCreate,
    RatingOut,
    RideCreate,
    RideOut,
    TokenOut,
    UserCreate,
    UserLogin,
    UserOut,
)
from app.services.payments import get_payment_adapter

router = APIRouter()
settings = get_settings()


@router.get("/health", response_model=HealthOut)
def health() -> HealthOut:
    return HealthOut(
        status="ok",
        app=settings.app_name,
        country=settings.default_country,
        currency=settings.currency,
        version=__version__,
    )


@router.post("/auth/register", response_model=TokenOut, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, db: Session = Depends(get_db)) -> TokenOut:
    if db.query(User).filter(User.phone == payload.phone).first():
        raise HTTPException(status_code=400, detail="Ce numéro est déjà inscrit")
    user = User(
        phone=payload.phone,
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
        role=payload.role,
        city=payload.city,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return TokenOut(access_token=create_access_token(user.id))


@router.post("/auth/login", response_model=TokenOut)
def login(payload: UserLogin, db: Session = Depends(get_db)) -> TokenOut:
    # Normalize like registration
    phone = UserCreate.normalize_phone(payload.phone)
    user = db.query(User).filter(User.phone == phone).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Téléphone ou mot de passe incorrect")
    return TokenOut(access_token=create_access_token(user.id))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> User:
    return user


@router.get("/cities", response_model=list[CityOut])
def list_cities(db: Session = Depends(get_db)) -> list[City]:
    return db.query(City).filter(City.is_active.is_(True)).order_by(City.name).all()


@router.get("/rides", response_model=list[RideOut])
def search_rides(
    origin: str | None = Query(default=None),
    destination: str | None = Query(default=None),
    departure_date: date | None = Query(default=None),
    mode: str | None = Query(default=None),
    db: Session = Depends(get_db),
) -> list[Ride]:
    q = (
        db.query(Ride)
        .options(joinedload(Ride.driver))
        .filter(Ride.is_active.is_(True), Ride.seats_available > 0)
    )
    if origin:
        q = q.filter(Ride.origin_city.ilike(f"%{origin.strip()}%"))
    if destination:
        q = q.filter(Ride.destination_city.ilike(f"%{destination.strip()}%"))
    if departure_date:
        q = q.filter(Ride.departure_date == departure_date)
    if mode:
        q = q.filter(Ride.mode == mode)
    return q.order_by(Ride.departure_date, Ride.departure_time).all()


@router.get("/rides/{ride_id}", response_model=RideOut)
def get_ride(ride_id: int, db: Session = Depends(get_db)) -> Ride:
    ride = (
        db.query(Ride)
        .options(joinedload(Ride.driver))
        .filter(Ride.id == ride_id)
        .first()
    )
    if not ride:
        raise HTTPException(status_code=404, detail="Trajet introuvable")
    return ride


@router.post("/rides", response_model=RideOut, status_code=status.HTTP_201_CREATED)
def publish_ride(
    payload: RideCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Ride:
    if payload.origin_city.strip().lower() == payload.destination_city.strip().lower():
        raise HTTPException(status_code=400, detail="Départ et arrivée doivent être différents")
    ride = Ride(
        driver_id=user.id,
        origin_city=payload.origin_city.strip().title(),
        destination_city=payload.destination_city.strip().title(),
        departure_date=payload.departure_date,
        departure_time=payload.departure_time,
        seats_total=payload.seats_total,
        seats_available=payload.seats_total,
        price_per_seat=payload.price_per_seat,
        mode=payload.mode,
        vehicle_info=payload.vehicle_info,
        meeting_point=payload.meeting_point,
        notes=payload.notes,
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
    return ride


@router.post("/rides/{ride_id}/book", response_model=BookingOut, status_code=status.HTTP_201_CREATED)
def book_ride(
    ride_id: int,
    payload: BookingCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Booking:
    ride = db.query(Ride).options(joinedload(Ride.driver)).filter(Ride.id == ride_id).first()
    if not ride or not ride.is_active:
        raise HTTPException(status_code=404, detail="Trajet introuvable")
    if ride.driver_id == user.id:
        raise HTTPException(status_code=400, detail="Vous ne pouvez pas réserver votre propre trajet")
    if payload.seats > ride.seats_available:
        raise HTTPException(status_code=400, detail="Pas assez de places disponibles")

    total = payload.seats * ride.price_per_seat
    payment_phone = payload.payment_phone or user.phone
    booking = Booking(
        ride_id=ride.id,
        passenger_id=user.id,
        seats=payload.seats,
        total_amount=total,
        status=BookingStatus.PENDING,
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
            joinedload(Booking.ride).joinedload(Ride.driver),
        )
        .filter(Booking.id == booking.id)
        .one()
    )
    return booking


@router.get("/me/bookings", response_model=list[BookingOut])
def my_bookings(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[Booking]:
    return (
        db.query(Booking)
        .options(
            joinedload(Booking.payment),
            joinedload(Booking.ride).joinedload(Ride.driver),
        )
        .filter(Booking.passenger_id == user.id)
        .order_by(Booking.created_at.desc())
        .all()
    )


@router.get("/me/rides", response_model=list[RideOut])
def my_rides(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[Ride]:
    return (
        db.query(Ride)
        .options(joinedload(Ride.driver))
        .filter(Ride.driver_id == user.id)
        .order_by(Ride.departure_date.desc())
        .all()
    )


@router.post("/payments/{payment_id}/confirm", response_model=PaymentOut)
def confirm_payment(
    payment_id: int,
    payload: PaymentConfirm,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Payment:
    payment = (
        db.query(Payment)
        .options(joinedload(Payment.booking))
        .filter(Payment.id == payment_id)
        .first()
    )
    if not payment:
        raise HTTPException(status_code=404, detail="Paiement introuvable")
    booking = payment.booking
    ride = db.get(Ride, booking.ride_id)
    if not ride:
        raise HTTPException(status_code=404, detail="Trajet lié introuvable")
    if booking.passenger_id != user.id and ride.driver_id != user.id:
        raise HTTPException(status_code=403, detail="Accès refusé")

    if payload.success:
        payment.status = PaymentStatus.SUCCESS
        booking.status = BookingStatus.PAID
        if payload.external_ref:
            payment.external_ref = payload.external_ref
    else:
        payment.status = PaymentStatus.FAILED
        # liberate seats on failure if still pending
        if booking.status == BookingStatus.PENDING:
            ride = db.get(Ride, booking.ride_id)
            if ride:
                ride.seats_available += booking.seats
            booking.status = BookingStatus.CANCELLED
    db.commit()
    db.refresh(payment)
    return payment


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