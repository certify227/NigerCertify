import os

# Base isolée en mémoire + reset à chaque lifespan TestClient.
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["RESET_DB_ON_START"] = "true"

from app.core.config import get_settings

get_settings.cache_clear()

# Recréer le moteur après changement d'URL (module déjà importable via get_settings).
from sqlalchemy.pool import StaticPool

from app.core import database as db_mod

db_mod.engine = db_mod.create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
db_mod.SessionLocal = db_mod.sessionmaker(
    autocommit=False, autoflush=False, bind=db_mod.engine
)

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c
