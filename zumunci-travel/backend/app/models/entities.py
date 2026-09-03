from __future__ import annotations

from datetime import date, datetime
from enum import Enum

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Enum as SAEnum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class UserRole(str, Enum):
    PASSENGER = "passenger"
    DRIVER = "driver"
    BOTH = "both"
    ADMIN = "admin"


class RideMode(str, Enum):
    CARPOOL = "carpool"
    BUSH_TAXI = "bush_taxi"
    BUS = "bus"


class BookingStatus(str, Enum):
    PENDING = "pending"
    PAID = "paid"
    CANCELLED = "cancelled"
    COMPLETED = "completed"


class PaymentStatus(str, Enum):
    INITIATED = "initiated"
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"


class PaymentProvider(str, Enum):
    ORANGE_MONEY = "orange_money"
    AIRTEL_MONEY = "airtel_money"
    MOOV_MONEY = "moov_money"
    CASH = "cash"


class VerificationStatus(str, Enum):
    UNVERIFIED = "unverified"
    PENDING = "pending"
    VERIFIED = "verified"
    REJECTED = "rejected"


class IdDocumentType(str, Enum):
    NATIONAL_ID = "national_id"
    PASSPORT = "passport"
    DRIVERS_LICENSE = "drivers_license"


class ReportReason(str, Enum):
    SCAM = "scam"
    INAPPROPRIATE_BEHAVIOR = "inappropriate_behavior"
    HARASSMENT = "harassment"
    OFF_PLATFORM_PAYMENT = "off_platform_payment"
    FAKE_PROFILE = "fake_profile"
    OTHER = "other"


class ReportStatus(str, Enum):
    OPEN = "open"
    REVIEWING = "reviewing"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    phone: Mapped[str] = mapped_column(String(20), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(120))
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[UserRole] = mapped_column(SAEnum(UserRole), default=UserRole.BOTH)
    city: Mapped[str | None] = mapped_column(String(80), nullable=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    verification_status: Mapped[VerificationStatus] = mapped_column(
        SAEnum(VerificationStatus), default=VerificationStatus.UNVERIFIED, index=True
    )
    id_document_type: Mapped[IdDocumentType | None] = mapped_column(SAEnum(IdDocumentType), nullable=True)
    id_document_number: Mapped[str | None] = mapped_column(String(64), nullable=True)
    id_full_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    verification_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    accepted_safety_charter: Mapped[bool] = mapped_column(Boolean, default=False)
    safety_charter_accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    phone_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    is_suspended: Mapped[bool] = mapped_column(Boolean, default=False)
    bio: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    rides: Mapped[list[Ride]] = relationship(back_populates="driver")
    bookings: Mapped[list[Booking]] = relationship(back_populates="passenger")
    ratings_received: Mapped[list[Rating]] = relationship(
        back_populates="reviewee", foreign_keys="Rating.reviewee_id"
    )
    reports_made: Mapped[list[SafetyReport]] = relationship(
        back_populates="reporter", foreign_keys="SafetyReport.reporter_id"
    )


class City(Base):
    __tablename__ = "cities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    region: Mapped[str] = mapped_column(String(80))
    latitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    longitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class Ride(Base):
    __tablename__ = "rides"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    driver_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    origin_city: Mapped[str] = mapped_column(String(80), index=True)
    destination_city: Mapped[str] = mapped_column(String(80), index=True)
    departure_date: Mapped[date] = mapped_column(Date, index=True)
    departure_time: Mapped[str] = mapped_column(String(5))  # HH:MM
    seats_total: Mapped[int] = mapped_column(Integer)
    seats_available: Mapped[int] = mapped_column(Integer)
    price_per_seat: Mapped[int] = mapped_column(Integer)  # XOF
    mode: Mapped[RideMode] = mapped_column(SAEnum(RideMode), default=RideMode.CARPOOL)
    vehicle_info: Mapped[str | None] = mapped_column(String(120), nullable=True)
    meeting_point: Mapped[str | None] = mapped_column(String(200), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    women_priority: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    driver: Mapped[User] = relationship(back_populates="rides")
    bookings: Mapped[list[Booking]] = relationship(back_populates="ride")


class Booking(Base):
    __tablename__ = "bookings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ride_id: Mapped[int] = mapped_column(ForeignKey("rides.id"), index=True)
    passenger_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    seats: Mapped[int] = mapped_column(Integer, default=1)
    total_amount: Mapped[int] = mapped_column(Integer)
    platform_fee: Mapped[int] = mapped_column(Integer, default=0)
    driver_amount: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[BookingStatus] = mapped_column(SAEnum(BookingStatus), default=BookingStatus.PENDING)
    contact_unlocked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    ride: Mapped[Ride] = relationship(back_populates="bookings")
    passenger: Mapped[User] = relationship(back_populates="bookings")
    payment: Mapped[Payment | None] = relationship(back_populates="booking", uselist=False)


class Payment(Base):
    __tablename__ = "payments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    booking_id: Mapped[int] = mapped_column(ForeignKey("bookings.id"), unique=True)
    provider: Mapped[PaymentProvider] = mapped_column(SAEnum(PaymentProvider))
    phone: Mapped[str] = mapped_column(String(20))
    amount: Mapped[int] = mapped_column(Integer)
    currency: Mapped[str] = mapped_column(String(8), default="XOF")
    status: Mapped[PaymentStatus] = mapped_column(SAEnum(PaymentStatus), default=PaymentStatus.INITIATED)
    external_ref: Mapped[str | None] = mapped_column(String(120), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    booking: Mapped[Booking] = relationship(back_populates="payment")


class Rating(Base):
    __tablename__ = "ratings"
    __table_args__ = (UniqueConstraint("booking_id", "reviewer_id", name="uq_rating_booking_reviewer"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    booking_id: Mapped[int] = mapped_column(ForeignKey("bookings.id"), index=True)
    reviewer_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    reviewee_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    score: Mapped[int] = mapped_column(Integer)  # 1-5
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    reviewee: Mapped[User] = relationship(back_populates="ratings_received", foreign_keys=[reviewee_id])


class SafetyReport(Base):
    __tablename__ = "safety_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    reporter_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    reported_user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    booking_id: Mapped[int | None] = mapped_column(ForeignKey("bookings.id"), nullable=True)
    reason: Mapped[ReportReason] = mapped_column(SAEnum(ReportReason))
    details: Mapped[str] = mapped_column(Text)
    status: Mapped[ReportStatus] = mapped_column(SAEnum(ReportStatus), default=ReportStatus.OPEN)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    reporter: Mapped[User] = relationship(back_populates="reports_made", foreign_keys=[reporter_id])
