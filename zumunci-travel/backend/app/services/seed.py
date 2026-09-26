"""Données de démarrage — toutes les régions du Niger + trajets démo."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.models.entities import (
    City,
    FieldAgent,
    IdDocumentType,
    Ride,
    RideMode,
    TransportCompany,
    User,
    UserRole,
    VerificationStatus,
)

# Chefs-lieux des 8 régions + villes secondaires + UEMOA live
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
    ("Madaoua", "Tahoua", 14.0731, 5.9600),
    ("Magaria", "Zinder", 12.9981, 8.9097),
    ("Filingué", "Tillabéri", 14.3500, 3.3167),
    ("N'Guigmi", "Diffa", 14.2520, 13.1100),
    ("Tchin-Tabaraden", "Tahoua", 15.8980, 5.7950),
    ("Ayorou", "Tillabéri", 14.7310, 0.9190),
    # UEMOA live (XOF)
    ("Ouagadougou", "UEMOA-BF", 12.3714, -1.5197),
    ("Bamako", "UEMOA-ML", 12.6392, -8.0029),
]


def _verified_user(**kwargs) -> User:
    now = datetime.now(timezone.utc)
    return User(
        is_verified=True,
        verification_status=VerificationStatus.VERIFIED,
        accepted_safety_charter=True,
        safety_charter_accepted_at=now,
        phone_verified=True,
        id_document_type=IdDocumentType.NATIONAL_ID,
        verification_notes="Compte démo pré-vérifié ZumunciTravel",
        **kwargs,
    )


def _ensure_user(db: Session, phone: str, factory) -> User:
    existing = db.query(User).filter_by(phone=phone).first()
    if existing:
        return existing
    user = factory()
    db.add(user)
    db.flush()
    return user


def seed_database(db: Session) -> None:
    if db.query(City).count() == 0:
        for name, region, lat, lon in NIGER_CITIES:
            db.add(City(name=name, region=region, latitude=lat, longitude=lon))
        db.commit()
    else:
        # Ajoute les villes UEMOA manquantes sans reset
        for name, region, lat, lon in NIGER_CITIES:
            if db.query(City).filter_by(name=name).first():
                continue
            db.add(City(name=name, region=region, latitude=lat, longitude=lon))
        db.commit()

    _ensure_user(
        db,
        "+22790000001",
        lambda: _verified_user(
            phone="+22790000001",
            full_name="Ibrahim Conducteur",
            password_hash=hash_password("zumunci123"),
            role=UserRole.DRIVER,
            city="Niamey",
            bio="Conducteur régulier Niamey–Maradi / Zinder.",
            id_document_number="NE-CNI-000001",
            id_full_name="Ibrahim Conducteur",
        ),
    )
    _ensure_user(
        db,
        "+22790000002",
        lambda: _verified_user(
            phone="+22790000002",
            full_name="Aïcha Voyageuse",
            password_hash=hash_password("zumunci123"),
            role=UserRole.PASSENGER,
            city="Niamey",
            id_document_number="NE-CNI-000002",
            id_full_name="Aïcha Voyageuse",
        ),
    )
    _ensure_user(
        db,
        "+22790000003",
        lambda: _verified_user(
            phone="+22790000003",
            full_name="Moussa Taxi Brousse",
            password_hash=hash_password("zumunci123"),
            role=UserRole.DRIVER,
            city="Zinder",
            bio="Liaisons Est : Zinder, Diffa, Agadez.",
            id_document_number="NE-CNI-000003",
            id_full_name="Moussa Taxi Brousse",
        ),
    )
    _ensure_user(
        db,
        "+22790000099",
        lambda: _verified_user(
            phone="+22790000099",
            full_name="Admin Zumunci",
            password_hash=hash_password("zumunci123"),
            role=UserRole.ADMIN,
            city="Niamey",
            id_document_number="NE-ADM-000099",
            id_full_name="Admin Zumunci",
        ),
    )
    _ensure_user(
        db,
        "+22790000004",
        lambda: User(
            phone="+22790000004",
            full_name="Nouveau Sans Verif",
            password_hash=hash_password("zumunci123"),
            role=UserRole.BOTH,
            city="Niamey",
            is_verified=False,
            verification_status=VerificationStatus.UNVERIFIED,
            accepted_safety_charter=False,
        ),
    )
    db.commit()

    def _ensure_company(slug: str, **kwargs) -> TransportCompany:
        existing = db.query(TransportCompany).filter_by(slug=slug).first()
        if existing:
            return existing
        company = TransportCompany(slug=slug, **kwargs)
        db.add(company)
        db.flush()
        return company

    rimbo = _ensure_company(
        "rimbo",
        name="Rimbo Transport",
        city_hub="Niamey",
        phone="+22720300001",
        description="Compagnie de bus inter-régionale — axes Niamey, Maradi, Zinder.",
    )
    sahel = _ensure_company(
        "sahel",
        name="Sahel Lines",
        city_hub="Zinder",
        phone="+22720510002",
        description="Liaisons Est : Zinder, Diffa, Agadez.",
    )
    azawad = _ensure_company(
        "azawad",
        name="Azawad Express",
        city_hub="Agadez",
        phone="+22720620003",
        description="Nord Niger — Agadez / Arlit (partenariat pilote).",
    )
    db.commit()

    if db.query(Ride).count() == 0:
        ibrahim = db.query(User).filter_by(phone="+22790000001").one()
        moussa = db.query(User).filter_by(phone="+22790000003").one()
        today = date.today()
        rides = [
            # Niamey
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
                women_priority=True,
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
                driver_id=ibrahim.id,
                origin_city="Niamey",
                destination_city="Tillabéri",
                departure_date=today + timedelta(days=2),
                departure_time="08:00",
                seats_total=3,
                seats_available=3,
                price_per_seat=3500,
                mode=RideMode.CARPOOL,
                meeting_point="Katako",
                women_priority=True,
            ),
            Ride(
                driver_id=ibrahim.id,
                origin_city="Niamey",
                destination_city="Tahoua",
                departure_date=today + timedelta(days=3),
                departure_time="05:45",
                seats_total=3,
                seats_available=2,
                price_per_seat=9000,
                mode=RideMode.CARPOOL,
                vehicle_info="Hyundai Tucson",
                meeting_point="Terminus Wadata",
            ),
            # Maradi / Zinder — compagnies bus
            Ride(
                driver_id=moussa.id,
                company_id=rimbo.id,
                origin_city="Maradi",
                destination_city="Zinder",
                departure_date=today + timedelta(days=1),
                departure_time="14:00",
                seats_total=12,
                seats_available=10,
                price_per_seat=4000,
                mode=RideMode.BUS,
                vehicle_info="Bus Rimbo 30 places",
                meeting_point="Station Maradi centre",
            ),
            Ride(
                driver_id=moussa.id,
                company_id=sahel.id,
                origin_city="Zinder",
                destination_city="Diffa",
                departure_date=today + timedelta(days=2),
                departure_time="06:00",
                seats_total=8,
                seats_available=5,
                price_per_seat=7000,
                mode=RideMode.BUSH_TAXI,
                vehicle_info="Hiace Sahel Lines",
                meeting_point="Gare de Zinder",
            ),
            # Agadez / Nord
            Ride(
                driver_id=moussa.id,
                company_id=sahel.id,
                origin_city="Zinder",
                destination_city="Agadez",
                departure_date=today + timedelta(days=3),
                departure_time="05:00",
                seats_total=8,
                seats_available=6,
                price_per_seat=10000,
                mode=RideMode.BUSH_TAXI,
                vehicle_info="Hiace Sahel Lines",
                meeting_point="Gare de Zinder",
                notes="Liaison Est–Nord.",
            ),
            Ride(
                driver_id=moussa.id,
                company_id=azawad.id,
                origin_city="Agadez",
                destination_city="Arlit",
                departure_date=today + timedelta(days=4),
                departure_time="07:30",
                seats_total=6,
                seats_available=4,
                price_per_seat=5000,
                mode=RideMode.BUSH_TAXI,
                meeting_point="Gare Agadez",
            ),
            # Retours / autres régions
            Ride(
                driver_id=ibrahim.id,
                origin_city="Maradi",
                destination_city="Niamey",
                departure_date=today + timedelta(days=4),
                departure_time="08:15",
                seats_total=3,
                seats_available=3,
                price_per_seat=7500,
                mode=RideMode.CARPOOL,
                vehicle_info="Hyundai Tucson",
                meeting_point="Gare Maradi",
                women_priority=True,
            ),
            Ride(
                driver_id=ibrahim.id,
                company_id=rimbo.id,
                origin_city="Dosso",
                destination_city="Gaya",
                departure_date=today + timedelta(days=5),
                departure_time="09:00",
                seats_total=2,
                seats_available=2,
                price_per_seat=2500,
                mode=RideMode.BUS,
                meeting_point="Gare Dosso",
            ),
        ]
        db.add_all(rides)
        db.commit()

    # Compte compagnie Rimbo (publie des bus)
    rimbo = db.query(TransportCompany).filter_by(slug="rimbo").first()
    if rimbo and not db.query(User).filter_by(phone="+22790000050").first():
        db.add(
            _verified_user(
                phone="+22790000050",
                full_name="Rimbo Ops Niamey",
                password_hash=hash_password("zumunci123"),
                role=UserRole.COMPANY,
                city="Niamey",
                bio="Compte compagnie Rimbo Transport — publications bus.",
                id_document_number="NE-CO-RIMBO",
                id_full_name="Rimbo Transport",
                company_id=rimbo.id,
            )
        )
        db.commit()

    # Trajets UEMOA démo (si absents)
    if rimbo and db.query(Ride).filter(Ride.destination_city == "Ouagadougou").count() == 0:
        company_user = db.query(User).filter_by(phone="+22790000050").first()
        ibrahim = db.query(User).filter_by(phone="+22790000001").one()
        driver_id = company_user.id if company_user else ibrahim.id
        today = date.today()
        db.add_all(
            [
                Ride(
                    driver_id=driver_id,
                    company_id=rimbo.id,
                    origin_city="Niamey",
                    destination_city="Ouagadougou",
                    departure_date=today + timedelta(days=2),
                    departure_time="06:00",
                    seats_total=40,
                    seats_available=28,
                    price_per_seat=12000,
                    mode=RideMode.BUS,
                    vehicle_info="Bus Rimbo UEMOA",
                    meeting_point="Gare routière de Niamey",
                    notes="Corridor XOF Niamey–Ouagadougou (pilote UEMOA).",
                ),
                Ride(
                    driver_id=driver_id,
                    company_id=rimbo.id,
                    origin_city="Niamey",
                    destination_city="Bamako",
                    departure_date=today + timedelta(days=3),
                    departure_time="05:30",
                    seats_total=40,
                    seats_available=30,
                    price_per_seat=18000,
                    mode=RideMode.BUS,
                    vehicle_info="Bus Rimbo UEMOA",
                    meeting_point="Gare routière de Niamey",
                    notes="Corridor XOF Niamey–Bamako (pilote UEMOA).",
                ),
            ]
        )
        db.commit()

    # Ambassadeurs gares (idempotent)
    demo_agents = [
        ("+22790110001", "Hadiza Ambassadeure", "Niamey", "Gare routière de Niamey", "fr,ha,dje", "Accueil KYC & Mobile Money"),
        ("+22790110002", "Amadou Gare Maradi", "Maradi", "Station Maradi centre", "fr,ha", "Orientation Rimbo / covoiturage"),
        ("+22790110003", "Fatima Zinder Hub", "Zinder", "Gare de Zinder", "fr,ha", "Liaisons Est Diffa / Agadez"),
        ("+22790110004", "Issoufou Agadez", "Agadez", "Gare Agadez", "fr,ha,tuar", "Nord Arlit — prudence nuit"),
        ("+22790110005", "Mariama Dosso", "Dosso", "Gare Dosso", "fr,dje", "Axe Niamey–Gaya"),
    ]
    for phone, name, city, station, langs, notes in demo_agents:
        if db.query(FieldAgent).filter_by(phone=phone).first():
            continue
        db.add(
            FieldAgent(
                phone=phone,
                full_name=name,
                city=city,
                station=station,
                languages=langs,
                notes=notes,
                is_active=True,
            )
        )
    db.commit()
