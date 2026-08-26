#!/usr/bin/env bash
# Migrations, seeds, collectstatic et superuser (déploiement natif sans Docker).
set -eu
[ -n "${BASH_VERSION:-}" ] && set -o pipefail

APP_DIR="${APP_DIR:-/opt/wifizone}"
BACKEND="$APP_DIR/wifizone/backend"
DEPLOY="$APP_DIR/wifizone/deploy/production"
VENV="${VENV:-$APP_DIR/venv}"
ENV_FILE="${ENV_FILE:-$DEPLOY/.env.production}"

if [ ! -f "$ENV_FILE" ]; then
  echo "Fichier d'environnement introuvable: $ENV_FILE"
  exit 1
fi

if [ ! -x "$VENV/bin/python" ]; then
  echo "Virtualenv introuvable: $VENV"
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

cd "$BACKEND"

echo "[wifizone] Migrations..."
"$VENV/bin/python" manage.py migrate --noinput

echo "[wifizone] Données initiales..."
"$VENV/bin/python" manage.py seed_plans
"$VENV/bin/python" manage.py seed_login_templates

echo "[wifizone] Fichiers statiques..."
"$VENV/bin/python" manage.py collectstatic --noinput

if [ "${CREATE_SUPERUSER:-false}" = "true" ]; then
  echo "[wifizone] Création superuser (si absent)..."
  "$VENV/bin/python" manage.py shell <<'PY'
import os
from django.contrib.auth import get_user_model

User = get_user_model()
username = os.environ.get("DJANGO_SUPERUSER_USERNAME", "")
email = os.environ.get("DJANGO_SUPERUSER_EMAIL", "")
password = os.environ.get("DJANGO_SUPERUSER_PASSWORD", "")

if not username or not password:
    print("CREATE_SUPERUSER=true mais identifiants manquants — ignoré.")
elif len(password) < 12:
    print("Mot de passe admin trop court (min 12 caractères) — superuser non créé.")
elif User.objects.filter(username=username).exists():
    print(f"Superuser '{username}' existe déjà.")
else:
    User.objects.create_superuser(username=username, email=email, password=password)
    print(f"Superuser '{username}' créé.")
PY
fi

echo "[wifizone] Bootstrap terminé."
