#!/usr/bin/env bash
set -eu
[ -n "${BASH_VERSION:-}" ] && set -o pipefail

OUT="${1:-.env.production}"
DOMAIN="${WIFI_DOMAIN:-wifi.nigercertify.com}"
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"
REDIS_HOST="${REDIS_HOST:-127.0.0.1}"
REDIS_PORT="${REDIS_PORT:-6379}"
APP_PORT="${WIFIZONE_HOST_PORT:-8004}"

gen() { openssl rand -base64 48 | tr -d '/+=' | head -c 64; }
gen_hex() { openssl rand -hex 32; }
fernet() {
  python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null \
    || openssl rand -base64 32
}

if [ -f "$OUT" ]; then
  echo "Le fichier $OUT existe déjà. Supprimez-le ou choisissez un autre chemin."
  exit 1
fi

SECRET=$(gen)
FERNET=$(fernet)
DB_PASS=$(gen_hex)
REDIS_PASS=$(gen_hex)
ADMIN_PASS=$(gen)

cat > "$OUT" <<EOF
# WiFiZone Pro — production native (sans Docker) — généré $(date -Iseconds)
# Domaine: ${DOMAIN}

COMPOSE_PROJECT_NAME=wifizone_prod

# --- Django ---
DJANGO_SECRET_KEY=${SECRET}
DJANGO_DEBUG=false
DJANGO_ALLOWED_HOSTS=${DOMAIN},www.${DOMAIN}
CSRF_TRUSTED_ORIGINS=https://${DOMAIN},https://www.${DOMAIN}
CORS_ALLOWED_ORIGINS=https://${DOMAIN},https://www.${DOMAIN}
SECURE_SSL_REDIRECT=true
SECURE_HSTS_SECONDS=31536000
ENABLE_API_DOCS=false
MIKROTIK_MOCK_MODE=false

FERNET_KEY=${FERNET}

# Superuser (premier déploiement uniquement — CREATE_SUPERUSER=true)
CREATE_SUPERUSER=true
DJANGO_SUPERUSER_USERNAME=admin
DJANGO_SUPERUSER_PASSWORD=${ADMIN_PASS}
DJANGO_SUPERUSER_EMAIL=admin@nigercertify.com

# --- Base de données (PostgreSQL système) ---
POSTGRES_DB=wifizone
POSTGRES_USER=wifizone
POSTGRES_PASSWORD=${DB_PASS}
DATABASE_URL=postgres://wifizone:${DB_PASS}@${DB_HOST}:${DB_PORT}/wifizone

# --- Redis système ---
REDIS_PASSWORD=${REDIS_PASS}
CELERY_BROKER_URL=redis://:${REDIS_PASS}@${REDIS_HOST}:${REDIS_PORT}/0
CELERY_RESULT_BACKEND=redis://:${REDIS_PASS}@${REDIS_HOST}:${REDIS_PORT}/0
CHANNEL_LAYER_URL=redis://:${REDIS_PASS}@${REDIS_HOST}:${REDIS_PORT}/1

# --- Email (SMTP — compléter si besoin) ---
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.nigercertify.com
EMAIL_PORT=587
EMAIL_USE_TLS=true
EMAIL_HOST_USER=
EMAIL_HOST_PASSWORD=
DEFAULT_FROM_EMAIL=noreply@nigercertify.com

# --- Nginx / TLS ---
NGINX_HOST=${DOMAIN}
DJANGO_ADMIN_URL=admin
JWT_ACCESS_HOURS=4
JWT_REFRESH_DAYS=7

# --- Gunicorn natif (ports 8000-8003 déjà utilisés sur ce serveur) ---
WIFIZONE_HOST_PORT=${APP_PORT}
APP_PORT=${APP_PORT}
ASGI_SERVER=gunicorn
GUNICORN_WORKERS=2
EOF

chmod 600 "$OUT"
echo "Fichier créé: $OUT (permissions 600)"
echo "Mode: natif (PostgreSQL/Redis sur ${DB_HOST}, app sur 127.0.0.1:${APP_PORT})"
echo "Domaine: https://${DOMAIN}"
echo "IMPORTANT — conservez ce mot de passe admin: ${ADMIN_PASS}"
echo "Complétez EMAIL_HOST_USER / EMAIL_HOST_PASSWORD si vous utilisez le reset MDP par email."
