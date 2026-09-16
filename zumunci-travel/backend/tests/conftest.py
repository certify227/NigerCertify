import os

# Schéma propre à chaque session de tests (avant import de l'app).
os.environ.setdefault("RESET_DB_ON_START", "true")

from app.core.config import get_settings

get_settings.cache_clear()

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c