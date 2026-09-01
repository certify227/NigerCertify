from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.entities import BookingStatus, PaymentProvider, PaymentStatus, RideMode, UserRole


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    phone: str = Field(min_length=8, max_length=20)
    full_name: str = Field(min_length=2, max_length=120)
    password: str = Field(min_length=6, max_length=128)
    city: str | None = None
    role: UserRole = UserRole.BOTH

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


class DriverBrief(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    full_name: str
    phone: str
    is_verified: bool
    city: str | None = None


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
    status: BookingStatus
    created_at: datetime
    ride: RideOut | None = None
    payment: PaymentOut | None = None


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


class HealthOut(BaseModel):
    status: Literal["ok"]
    app: str
    country: str
    currency: str
    version: str


class MessageOut(BaseModel):
    message: str