#!/bin/sh
set -eu

echo "[wifizone] Migrations..."
python manage.py migrate --noinput

echo "[wifizone] Données initiales..."
python manage.py seed_plans
python manage.py seed_login_templates

echo "[wifizone] Fichiers statiques..."
python manage.py collectstatic --noinput

if [ "${CREATE_SUPERUSER:-false}" = "true" ]; then
  python manage.py shell <<'PY'
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

echo "[wifizone] Démarrage Daphne..."
exec daphne -b 0.0.0.0 -p 8000 --proxy-headers config.asgi:application
