#!/usr/bin/env bash
# Génère des secrets pour .env.production (ne commitez jamais le fichier généré).
set -euo pipefail

OUT="${1:-.env.production}"

gen() { openssl rand -base64 48 | tr -d '/+=' | head -c 64; }
gen_hex() { openssl rand -hex 32; }
fernet() { python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null || openssl rand -base64 32; }

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
# WiFiZone Pro — production (généré $(date -Iseconds))
# Copiez vers: deploy/production/.env.production

COMPOSE_PROJECT_NAME=wifizone_prod

# --- Django ---
DJANGO_SECRET_KEY=${SECRET}
DJANGO_DEBUG=false
DJANGO_ALLOWED_HOSTS=votre-domaine.com,www.votre-domaine.com
CSRF_TRUSTED_ORIGINS=https://votre-domaine.com,https://www.votre-domaine.com
CORS_ALLOWED_ORIGINS=https://votre-domaine.com
SECURE_SSL_REDIRECT=true
SECURE_HSTS_SECONDS=31536000
ENABLE_API_DOCS=false
MIKROTIK_MOCK_MODE=false

FERNET_KEY=${FERNET}

# Superuser (premier déploiement uniquement — CREATE_SUPERUSER=true)
CREATE_SUPERUSER=true
DJANGO_SUPERUSER_USERNAME=admin
DJANGO_SUPERUSER_PASSWORD=${ADMIN_PASS}
DJANGO_SUPERUSER_EMAIL=admin@votre-domaine.com

# --- Base de données ---
POSTGRES_DB=wifizone
POSTGRES_USER=wifizone
POSTGRES_PASSWORD=${DB_PASS}
DATABASE_URL=postgres://wifizone:${DB_PASS}@db:5432/wifizone

# --- Redis ---
REDIS_PASSWORD=${REDIS_PASS}
CELERY_BROKER_URL=redis://:${REDIS_PASS}@redis:6379/0
CELERY_RESULT_BACKEND=redis://:${REDIS_PASS}@redis:6379/0
CHANNEL_LAYER_URL=redis://:${REDIS_PASS}@redis:6379/1

# --- Email (exemple SMTP) ---
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.votre-domaine.com
EMAIL_PORT=587
EMAIL_USE_TLS=true
EMAIL_HOST_USER=
EMAIL_HOST_PASSWORD=
DEFAULT_FROM_EMAIL=noreply@votre-domaine.com

# --- Nginx / TLS ---
NGINX_HOST=votre-domaine.com
DJANGO_ADMIN_URL=admin
JWT_ACCESS_HOURS=4
JWT_REFRESH_DAYS=7
EOF

chmod 600 "$OUT"
echo "Fichier créé: $OUT (permissions 600)"
echo "IMPORTANT — conservez ce mot de passe admin: ${ADMIN_PASS}"
echo "Modifiez DJANGO_ALLOWED_HOSTS, CSRF_TRUSTED_ORIGINS et NGINX_HOST avant déploiement."
