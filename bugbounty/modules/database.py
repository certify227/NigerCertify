"""Base de données SQLite pour historique des scans."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

from .utils import Finding


class ScanDatabase:
    """Stocke les scans et findings en SQLite."""

    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or Path(__file__).parent.parent / "data" / "bountystrike.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    duration REAL,
                    total_findings INTEGER,
                    critical INTEGER DEFAULT 0,
                    high INTEGER DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    title TEXT,
                    severity TEXT,
                    category TEXT,
                    url TEXT,
                    description TEXT,
                    evidence TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                );
            """)

    def save_scan(self, target: str, findings: list[Finding], duration: float) -> int:
        counts = {s: sum(1 for f in findings if f.severity == s) for s in ("critical", "high", "medium", "low", "info")}
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute(
                "INSERT INTO scans (target, started_at, duration, total_findings, critical, high) VALUES (?,?,?,?,?,?)",
                (target, datetime.utcnow().isoformat(), duration, len(findings), counts.get("critical", 0), counts.get("high", 0)),
            )
            scan_id = cur.lastrowid
            for f in findings:
                conn.execute(
                    "INSERT INTO findings (scan_id, title, severity, category, url, description, evidence) VALUES (?,?,?,?,?,?,?)",
                    (scan_id, f.title, f.severity, f.category, f.url, f.description, f.evidence),
                )
            return scan_id or 0

    def get_recent_scans(self, limit: int = 20) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def get_findings(self, scan_id: int) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,)).fetchall()
            return [dict(r) for r in rows]

    def get_stats(self) -> dict:
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            critical = conn.execute("SELECT COUNT(*) FROM findings WHERE severity='critical'").fetchone()[0]
            return {"scans": total, "findings": findings, "critical": critical}
