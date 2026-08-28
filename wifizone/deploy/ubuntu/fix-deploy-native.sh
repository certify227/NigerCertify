#!/usr/bin/env bash
# Correction automatique du déploiement WiFiZone Pro (natif, sans Docker)
# Usage: sudo bash deploy/ubuntu/fix-deploy-native.sh
set -eu
[ -n "${BASH_VERSION:-}" ] && set -o pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Exécutez en root: sudo bash $0"
  exit 1
fi

APP_DIR="${APP_DIR:-/opt/wifizone}"
WIFIZONE_USER="${WIFIZONE_USER:-adminsys0}"
WIFIZONE_GROUP="${WIFIZONE_GROUP:-$WIFIZONE_USER}"
VENV="${VENV:-$APP_DIR/venv}"
GIT_BRANCH="${GIT_BRANCH:-cursor/wifizone-saas-django-3301}"
DOMAIN="${WIFI_DOMAIN:-wifi.nigercertify.com}"
SKIP_DB_SETUP="${SKIP_DB_SETUP:-true}"
SKIP_REDIS_SETUP="${SKIP_REDIS_SETUP:-true}"
INSTALL_SSL="${INSTALL_SSL:-auto}"

DEPLOY="$APP_DIR/wifizone/deploy/production"
ENV_FILE="$DEPLOY/.env.production"
BACKEND="$APP_DIR/wifizone/backend"
UBUNTU_DIR="$APP_DIR/wifizone/deploy/ubuntu"

echo "=== WiFiZone — correction déploiement natif ==="

# Git safe.directory
git config --global --add safe.directory "$APP_DIR" 2>/dev/null || true
if id "$WIFIZONE_USER" >/dev/null 2>&1; then
  chown -R "$WIFIZONE_USER:$WIFIZONE_GROUP" "$APP_DIR" 2>/dev/null || true
fi

# Mise à jour code
if [ -d "$APP_DIR/.git" ]; then
  git -C "$APP_DIR" fetch origin
  git -C "$APP_DIR" checkout "$GIT_BRANCH"
  git -C "$APP_DIR" pull origin "$GIT_BRANCH"
  echo "✅ Code à jour ($GIT_BRANCH)"
else
  echo "❌ Clonez d'abord le dépôt dans $APP_DIR"
  exit 1
fi

chmod +x "$UBUNTU_DIR"/*.sh "$DEPLOY"/scripts/*.sh 2>/dev/null || true

# Secrets
if [ ! -f "$ENV_FILE" ]; then
  echo "Génération .env.production..."
  WIFI_DOMAIN="$DOMAIN" bash "$DEPLOY/scripts/generate-secrets-native.sh" "$ENV_FILE"
  chown "$WIFIZONE_USER:$WIFIZONE_GROUP" "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  echo "⚠️  Éditez $ENV_FILE puis relancez ce script."
  exit 0
fi

chmod 600 "$ENV_FILE"
missing=0
for key in POSTGRES_PASSWORD REDIS_PASSWORD DJANGO_SECRET_KEY FERNET_KEY DATABASE_URL; do
  val="$(grep -E "^${key}=" "$ENV_FILE" | head -1 | cut -d= -f2- || true)"
  if [ -z "$val" ]; then
    echo "❌ Variable vide: $key"
    missing=1
  fi
done
if [ "$missing" -eq 1 ]; then
  echo "Regénérez: mv $ENV_FILE ${ENV_FILE}.bak && bash $DEPLOY/scripts/generate-secrets-native.sh $ENV_FILE"
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

APP_PORT="${WIFIZONE_HOST_PORT:-8004}"
GUNICORN_WORKERS="${GUNICORN_WORKERS:-2}"

# Paquets minimaux
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-dev build-essential libpq-dev curl git nginx redis-server postgresql >/dev/null

# Virtualenv
if [ ! -x "$VENV/bin/python" ]; then
  python3 -m venv "$VENV"
fi
"$VENV/bin/pip" install -q --upgrade pip wheel
"$VENV/bin/pip" install -q -r "$BACKEND/requirements.txt"

mkdir -p "$BACKEND/media" "$BACKEND/staticfiles"
chown -R "$WIFIZONE_USER:$WIFIZONE_GROUP" "$VENV" "$APP_DIR" "$BACKEND/media" "$BACKEND/staticfiles"

# Bootstrap Django
sudo -u "$WIFIZONE_USER" env APP_DIR="$APP_DIR" VENV="$VENV" ENV_FILE="$ENV_FILE" \
  bash "$UBUNTU_DIR/bootstrap-native.sh"

# Systemd
install_systemd() {
  local src="$1"
  local dest="/etc/systemd/system/$(basename "$src")"
  sed \
    -e "s|__WIFIZONE_USER__|$WIFIZONE_USER|g" \
    -e "s|__WIFIZONE_GROUP__|$WIFIZONE_GROUP|g" \
    -e "s|__BACKEND_DIR__|$BACKEND|g" \
    -e "s|__ENV_FILE__|$ENV_FILE|g" \
    -e "s|__VENV__|$VENV|g" \
    -e "s|__APP_PORT__|$APP_PORT|g" \
    -e "s|__GUNICORN_WORKERS__|$GUNICORN_WORKERS|g" \
    "$src" > "$dest"
}

for svc in wifizone-web wifizone-celery-worker wifizone-celery-beat; do
  install_systemd "$UBUNTU_DIR/systemd/${svc}.service"
done

systemctl daemon-reload
systemctl enable wifizone-web wifizone-celery-worker wifizone-celery-beat
systemctl restart wifizone-web wifizone-celery-worker wifizone-celery-beat

sleep 2
if curl -sf --max-time 10 "http://127.0.0.1:${APP_PORT}/" >/dev/null; then
  echo "✅ Backend OK sur 127.0.0.1:${APP_PORT}"
else
  echo "❌ Backend ne répond pas — logs:"
  journalctl -u wifizone-web -n 25 --no-pager || true
  exit 1
fi

# Nginx
mkdir -p /etc/nginx/snippets
cp "$APP_DIR/wifizone/deploy/nginx-host/proxy-params.conf" /etc/nginx/snippets/proxy-params.conf
cp "$APP_DIR/wifizone/deploy/nginx-host/wifi.nigercertify.com.conf" \
  "/etc/nginx/sites-available/${DOMAIN}"
ln -sf "/etc/nginx/sites-available/${DOMAIN}" "/etc/nginx/sites-enabled/${DOMAIN}"

# SSL — certificat dédié ou adaptation
CERT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
if [ ! -f "$CERT" ] && [ "$INSTALL_SSL" != "skip" ]; then
  if command -v certbot >/dev/null; then
    echo "Demande certificat SSL pour ${DOMAIN}..."
    certbot certonly --nginx \
      -d "${DOMAIN}" -d "www.${DOMAIN}" \
      --non-interactive --agree-tos \
      --email "${CERTBOT_EMAIL:-admin@nigercertify.com}" \
      --keep-until-expiring 2>/dev/null \
      || certbot certonly --webroot -w /var/www/html \
        -d "${DOMAIN}" -d "www.${DOMAIN}" \
        --non-interactive --agree-tos \
        --email "${CERTBOT_EMAIL:-admin@nigercertify.com}" \
      || echo "⚠️  Certbot a échoué — configurez SSL manuellement"
  else
    echo "⚠️  certbot absent — apt install certbot python3-certbot-nginx"
  fi
fi

# Si certificat wifi.* absent, config HTTP-only temporaire pour éviter 404
if [ ! -f "$CERT" ]; then
  echo "⚠️  Pas de cert SSL pour ${DOMAIN} — activation HTTP proxy (sans HTTPS)"
  cat > "/etc/nginx/sites-available/${DOMAIN}" <<NGINX
upstream wifizone_backend {
    server 127.0.0.1:${APP_PORT};
    keepalive 16;
}

server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN} www.${DOMAIN};

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location /ws/ {
        proxy_pass http://wifizone_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        include /etc/nginx/snippets/proxy-params.conf;
        proxy_read_timeout 86400;
    }

    location / {
        proxy_pass http://wifizone_backend;
        include /etc/nginx/snippets/proxy-params.conf;
    }
}
NGINX
fi

nginx -t
systemctl reload nginx
echo "✅ Nginx rechargé"

echo ""
echo "=== Résultat ==="
bash "$UBUNTU_DIR/diagnose-native.sh" || true
echo ""
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 "http://${DOMAIN}/" 2>/dev/null || echo '000')"
echo "Test http://${DOMAIN}/ → HTTP ${code}"
if [ "$code" = "200" ] || [ "$code" = "302" ]; then
  echo "✅ Déploiement corrigé"
else
  echo "Si HTTP ≠ 200/302, vérifiez DNS et SSL (certbot)."
fi
