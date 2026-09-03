from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.entities import (
    BookingStatus,
    IdDocumentType,
    PaymentProvider,
    PaymentStatus,
    ReportReason,
    ReportStatus,
    RideMode,
    UserRole,
    VerificationStatus,
)


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    phone: str = Field(min_length=8, max_length=20)
    full_name: str = Field(min_length=2, max_length=120)
    password: str = Field(min_length=6, max_length=128)
    city: str | None = None
    role: UserRole = UserRole.BOTH
    accept_safety_charter: bool = False

    @field_validator("phone")
    @classmethod
    def normalize_phone(cls, v: str) -> str:
        digits = "".join(ch for ch in v if ch.isdigit() or ch == "+")
        if digits.startswith("00"):
            digits = "+" + digits[2:]
        if digits.startswith("9") and len(digits) == 8:
            digits = "+227" + digits
        if digits.startswith("227") and not digits.startswith("+"):
            digits = "+" + digits
        if not digits.startswith("+227") and len(digits) == 8:
            digits = "+227" + digits
        return digits


class UserLogin(BaseModel):
    phone: str
    password: str


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    phone: str
    full_name: str
    role: UserRole
    city: str | None
    is_verified: bool
    verification_status: VerificationStatus
    accepted_safety_charter: bool
    phone_verified: bool
    is_suspended: bool
    bio: str | None = None
    created_at: datetime


class CityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    region: str
    latitude: float | None = None
    longitude: float | None = None


class RideCreate(BaseModel):
    origin_city: str
    destination_city: str
    departure_date: date
    departure_time: str = Field(pattern=r"^\d{2}:\d{2}$")
    seats_total: int = Field(ge=1, le=50)
    price_per_seat: int = Field(ge=500, le=200_000)
    mode: RideMode = RideMode.CARPOOL
    vehicle_info: str | None = None
    meeting_point: str | None = None
    notes: str | None = None
    women_priority: bool = False


class DriverBrief(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    full_name: str
    phone: str | None = None
    is_verified: bool
    verification_status: VerificationStatus
    city: str | None = None
    contact_hidden: bool = True


class RideOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    origin_city: str
    destination_city: str
    departure_date: date
    departure_time: str
    seats_total: int
    seats_available: int
    price_per_seat: int
    currency: str = "XOF"
    mode: RideMode
    vehicle_info: str | None
    meeting_point: str | None
    notes: str | None
    women_priority: bool = False
    night_departure: bool = False
    is_active: bool
    driver: DriverBrief


class BookingCreate(BaseModel):
    seats: int = Field(default=1, ge=1, le=10)
    payment_provider: PaymentProvider = PaymentProvider.ORANGE_MONEY
    payment_phone: str | None = None


class PaymentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    provider: PaymentProvider
    phone: str
    amount: int
    currency: str
    status: PaymentStatus
    external_ref: str | None
    created_at: datetime


class BookingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ride_id: int
    seats: int
    total_amount: int
    platform_fee: int = 0
    driver_amount: int = 0
    status: BookingStatus
    contact_unlocked: bool
    created_at: datetime
    ride: RideOut | None = None
    payment: PaymentOut | None = None
    driver_phone: str | None = None
    passenger_phone: str | None = None
    driver_whatsapp_url: str | None = None


class PaymentConfirm(BaseModel):
    success: bool = True
    external_ref: str | None = None


class RatingCreate(BaseModel):
    score: int = Field(ge=1, le=5)
    comment: str | None = Field(default=None, max_length=500)


class RatingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    score: int
    comment: str | None
    created_at: datetime


class VerificationSubmit(BaseModel):
    id_document_type: IdDocumentType
    id_document_number: str = Field(min_length=4, max_length=64)
    id_full_name: str = Field(min_length=2, max_length=120)
    accept_safety_charter: bool = True


class VerificationReview(BaseModel):
    approve: bool
    notes: str | None = None


class AcceptCharterIn(BaseModel):
    accept: bool = True


class SafetyReportCreate(BaseModel):
    reported_user_id: int
    reason: ReportReason
    details: str = Field(min_length=10, max_length=2000)
    booking_id: int | None = None


class SafetyReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    reported_user_id: int
    reason: ReportReason
    details: str
    status: ReportStatus
    booking_id: int | None
    created_at: datetime


class SafetyCharterOut(BaseModel):
    title: str
    version: str
    rules: list[str]


class HealthOut(BaseModel):
    status: Literal["ok"]
    app: str
    country: str
    currency: str
    version: str


class MessageOut(BaseModel):
    message: str


class ContactRevealOut(BaseModel):
    booking_id: int
    contact_unlocked: bool
    driver_name: str | None = None
    driver_phone: str | None = None
    passenger_name: str | None = None
    passenger_phone: str | None = None
    driver_whatsapp_url: str | None = None
    passenger_whatsapp_url: str | None = None
    warning: str


class ProductConfigOut(BaseModel):
    app: str
    pilot_mode: bool
    pilot_hub: str
    national_coverage: bool
    regions: list[str]
    service_cities: list[str]
    pilot_corridors: list[str]
    commission_rate: float
    currency: str
    kyc_sla_hours: int
    cash_allowed_modes: list[str]
    night_start_hour: int
    night_end_hour: int
    default_locale: str
    payment_providers: list[str]
