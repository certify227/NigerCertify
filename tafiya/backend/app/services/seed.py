"""Données de démarrage — villes du Niger + trajets démo."""

from __future__ import annotations

from datetime import date, timedelta

from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.models.entities import City, Ride, RideMode, User, UserRole

NIGER_CITIES = [
    ("Niamey", "Niamey", 13.5127, 2.1126),
    ("Maradi", "Maradi", 13.4833, 7.1000),
    ("Zinder", "Zinder", 13.8053, 8.9883),
    ("Tahoua", "Tahoua", 14.8888, 5.2692),
    ("Agadez", "Agadez", 16.9736, 7.9911),
    ("Dosso", "Dosso", 13.0490, 3.1937),
    ("Diffa", "Diffa", 13.3154, 12.6113),
    ("Tillabéri", "Tillabéri", 14.2120, 1.4543),
    ("Birni N'Konni", "Tahoua", 13.7950, 5.2500),
    ("Tessaoua", "Maradi", 13.7531, 7.9864),
    ("Gaya", "Dosso", 11.8844, 3.4492),
    ("Arlit", "Agadez", 18.7391, 7.3853),
]


def seed_database(db: Session) -> None:
    if db.query(City).count() == 0:
        for name, region, lat, lon in NIGER_CITIES:
            db.add(City(name=name, region=region, latitude=lat, longitude=lon))
        db.commit()

    if db.query(User).count() == 0:
        demo_users = [
            User(
                phone="+22790000001",
                full_name="Ibrahim Conducteur",
                password_hash=hash_password("tafiya123"),
                role=UserRole.DRIVER,
                city="Niamey",
                is_verified=True,
                bio="Conducteur régulier Niamey–Maradi. Véhicule climatisé.",
            ),
            User(
                phone="+22790000002",
                full_name="Aïcha Voyageuse",
                password_hash=hash_password("tafiya123"),
                role=UserRole.PASSENGER,
                city="Niamey",
                is_verified=True,
            ),
            User(
                phone="+22790000003",
                full_name="Moussa Taxi Brousse",
                password_hash=hash_password("tafiya123"),
                role=UserRole.DRIVER,
                city="Zinder",
                is_verified=True,
                bio="Liaisons Zinder–Agadez chaque semaine.",
            ),
        ]
        db.add_all(demo_users)
        db.commit()

    if db.query(Ride).count() == 0:
        ibrahim = db.query(User).filter_by(phone="+22790000001").one()
        moussa = db.query(User).filter_by(phone="+22790000003").one()
        today = date.today()
        rides = [
            Ride(
                driver_id=ibrahim.id,
                origin_city="Niamey",
                destination_city="Maradi",
                departure_date=today + timedelta(days=1),
                departure_time="06:30",
                seats_total=3,
                seats_available=3,
                price_per_seat=7500,
                mode=RideMode.CARPOOL,
                vehicle_info="Toyota Corolla 2018",
                meeting_point="Gare routière de Niamey",
                notes="Départ ponctuel. Bagage cabine inclus.",
            ),
            Ride(
                driver_id=ibrahim.id,
                origin_city="Niamey",
                destination_city="Dosso",
                departure_date=today + timedelta(days=2),
                departure_time="07:00",
                seats_total=2,
                seats_available=2,
                price_per_seat=3000,
                mode=RideMode.CARPOOL,
                vehicle_info="Toyota Corolla 2018",
                meeting_point="Nouveau marché",
            ),
            Ride(
                driver_id=moussa.id,
                origin_city="Zinder",
                destination_city="Agadez",
                departure_date=today + timedelta(days=3),
                departure_time="05:00",
                seats_total=8,
                seats_available=6,
                price_per_seat=10000,
                mode=RideMode.BUSH_TAXI,
                vehicle_info="Hiace 14 places",
                meeting_point="Gare de Zinder",
                notes="Places restantes limitées le vendredi.",
            ),
            Ride(
                driver_id=moussa.id,
                origin_city="Maradi",
                destination_city="Zinder",
                departure_date=today + timedelta(days=1),
                departure_time="14:00",
                seats_total=12,
                seats_available=10,
                price_per_seat=4000,
                mode=RideMode.BUS,
                vehicle_info="Bus 30 places",
                meeting_point="Station Maradi centre",
            ),
            Ride(
                driver_id=ibrahim.id,
                origin_city="Niamey",
                destination_city="Tahoua",
                departure_date=today + timedelta(days=4),
                departure_time="08:15",
                seats_total=3,
                seats_available=3,
                price_per_seat=9000,
                mode=RideMode.CARPOOL,
                vehicle_info="Hyundai Tucson",
                meeting_point="Terminus Wadata",
            ),
        ]
        db.add_all(rides)
        db.commit()