"""Contexte d'authentification pour scans authentifiés."""

from __future__ import annotations

import requests


def apply_auth(
    session: requests.Session,
    bearer: str | None = None,
    cookie: str | None = None,
    auth_header: str | None = None,
) -> requests.Session:
    """Applique l'authentification à la session HTTP."""
    if bearer:
        token = bearer if bearer.startswith("Bearer ") else f"Bearer {bearer}"
        session.headers["Authorization"] = token
    if auth_header and ":" in auth_header:
        key, val = auth_header.split(":", 1)
        session.headers[key.strip()] = val.strip()
    if cookie:
        for part in cookie.split(";"):
            part = part.strip()
            if "=" in part:
                name, value = part.split("=", 1)
                session.cookies.set(name.strip(), value.strip())
    return session
