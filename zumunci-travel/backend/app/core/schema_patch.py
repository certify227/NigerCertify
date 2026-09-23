"""Migrations légères SQLite sans Alembic (ajout de colonnes)."""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.engine import Engine


def ensure_sqlite_columns(engine: Engine) -> None:
    """Ajoute les colonnes manquantes sur SQLite (dev / demo)."""
    if not str(engine.url).startswith("sqlite"):
        return

    statements = [
        ("users", "id_document_image", "TEXT"),
        ("users", "last_sms_at", "DATETIME"),
    ]
    with engine.begin() as conn:
        for table, column, coltype in statements:
            rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
            existing = {r[1] for r in rows}
            if column not in existing:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}"))

        # Table notifications si absente
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
