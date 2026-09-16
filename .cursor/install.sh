#!/usr/bin/env bash
# Idempotent bootstrap for the Niger Certify monorepo Cloud Agent environment.
# Sets up per-project Python virtualenvs and Node dependencies, then prepares
# local SQLite databases and seed data for the Django backends.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PY="${PYTHON:-python3}"

log() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

# --- 0. System packages required for Python virtualenvs / native wheels ----
# The default base image ships python3.12 without the venv/ensurepip module.
if ! "$PY" -c "import ensurepip" >/dev/null 2>&1; then
  log "Installing system packages (python venv + build toolchain)"
  sudo apt-get update -y
  sudo apt-get install -y --no-install-recommends \
    python3-venv python3.12-venv python3-dev build-essential
fi

# --- 1. Shared venv: root offensive tools + scanners + bugbounty ------------
log "Python venv: root tools / scanners / bugbounty"
$PY -m venv .venv
./.venv/bin/pip install --quiet --upgrade pip
./.venv/bin/pip install --quiet -r requirements.txt
./.venv/bin/pip install --quiet -r bugbounty/requirements.txt

# --- 2. CodeQuest (codely) backend: Django + DRF ---------------------------
if [ -f codely/backend/requirements.txt ]; then
  log "CodeQuest backend (Django, SQLite dev)"
  $PY -m venv codely/backend/.venv
  codely/backend/.venv/bin/pip install --quiet --upgrade pip
  codely/backend/.venv/bin/pip install --quiet -r codely/backend/requirements.txt
  (
    cd codely/backend
    export DJANGO_DEBUG=true
    unset DATABASE_URL || true
    ./.venv/bin/python manage.py migrate --noinput
    ./.venv/bin/python manage.py seed_full_content --force
    DJANGO_SUPERUSER_USERNAME=admin \
    DJANGO_SUPERUSER_EMAIL=admin@codequest.app \
    DJANGO_SUPERUSER_PASSWORD=admin1234 \
    ./.venv/bin/python manage.py shell -c "
from django.contrib.auth import get_user_model
U = get_user_model()
if not U.objects.filter(username='admin').exists():
    U.objects.create_superuser('admin', 'admin@codequest.app', 'admin1234')
    print('superuser admin created')
"
  )
fi

# --- 3. WiFiZone backend: Django + Channels/Celery (mock MikroTik) ---------
if [ -f wifizone/backend/requirements.txt ]; then
  log "WiFiZone backend (Django, SQLite dev, MikroTik mock)"
  $PY -m venv wifizone/backend/.venv
  wifizone/backend/.venv/bin/pip install --quiet --upgrade pip
  wifizone/backend/.venv/bin/pip install --quiet -r wifizone/backend/requirements.txt
  (
    cd wifizone/backend
    export DJANGO_DEBUG=true MIKROTIK_MOCK_MODE=true
    unset DATABASE_URL || true
    ./.venv/bin/python manage.py migrate --noinput
    ./.venv/bin/python manage.py seed_plans
    ./.venv/bin/python manage.py seed_login_templates
    DJANGO_SUPERUSER_USERNAME=admin \
    DJANGO_SUPERUSER_EMAIL=admin@wifizone.local \
    DJANGO_SUPERUSER_PASSWORD=admin1234 \
    ./.venv/bin/python manage.py shell -c "
from django.contrib.auth import get_user_model
U = get_user_model()
if not U.objects.filter(username='admin').exists():
    U.objects.create_superuser('admin', 'admin@wifizone.local', 'admin1234')
    print('superuser admin created')
"
  )
fi

# --- 4. ZumunciTravel backend: FastAPI + SQLAlchemy ------------------------
if [ -f zumunci-travel/backend/requirements.txt ]; then
  log "ZumunciTravel backend (FastAPI, SQLite dev)"
  $PY -m venv zumunci-travel/backend/.venv
  zumunci-travel/backend/.venv/bin/pip install --quiet --upgrade pip
  zumunci-travel/backend/.venv/bin/pip install --quiet -r zumunci-travel/backend/requirements.txt
fi

# --- 5. ZumunciTravel frontend: React + Vite -------------------------------
if [ -f zumunci-travel/frontend/package.json ]; then
  log "ZumunciTravel frontend (React + Vite)"
  (cd zumunci-travel/frontend && (npm ci || npm install))
fi

# --- 6. Photoshop Creator Pack: Node UXP plugin (test harness) -------------
if [ -f photoshop-creator-pack/package.json ]; then
  log "Photoshop Creator Pack (Node)"
  (cd photoshop-creator-pack && (npm ci 2>/dev/null || npm install))
fi

log "Install complete."
