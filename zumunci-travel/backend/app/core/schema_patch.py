"""Migrations légères SQLite sans Alembic (ajout de colonnes)."""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.engine import Engine


def ensure_sqlite_columns(engine: Engine) -> None:
    """Ajoute les colonnes / tables manquantes sur SQLite (dev / demo)."""
    if not str(engine.url).startswith("sqlite"):
        return

    statements = [
        ("users", "id_document_image", "TEXT"),
        ("users", "last_sms_at", "DATETIME"),
        ("rides", "company_id", "INTEGER"),
        ("bookings", "insurance_fee", "INTEGER DEFAULT 0"),
        ("bookings", "with_insurance", "BOOLEAN DEFAULT 0"),
    ]
    with engine.begin() as conn:
        for table, column, coltype in statements:
            rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
            existing = {r[1] for r in rows}
            if column not in existing:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}"))

        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS notifications (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    channel VARCHAR(20) NOT NULL DEFAULT 'sms',
                    title VARCHAR(120) NOT NULL,
                    body TEXT NOT NULL,
                    booking_id INTEGER,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS transport_companies (
                    id INTEGER PRIMARY KEY,
                    slug VARCHAR(64) NOT NULL UNIQUE,
                    name VARCHAR(120) NOT NULL UNIQUE,
                    city_hub VARCHAR(80),
                    phone VARCHAR(20),
                    description TEXT,
                    is_verified BOOLEAN DEFAULT 1,
                    is_active BOOLEAN DEFAULT 1,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS field_agents (
                    id INTEGER PRIMARY KEY,
                    full_name VARCHAR(120) NOT NULL,
                    phone VARCHAR(20) NOT NULL UNIQUE,
                    city VARCHAR(80) NOT NULL,
                    station VARCHAR(160) NOT NULL,
                    languages VARCHAR(120) DEFAULT 'fr,ha',
                    is_active BOOLEAN DEFAULT 1,
                    notes TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS ride_alerts (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    origin_city VARCHAR(80) NOT NULL,
                    destination_city VARCHAR(80) NOT NULL,
                    max_price INTEGER,
                    is_active BOOLEAN DEFAULT 1,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
                """
            )
        )
