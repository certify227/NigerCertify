#!/usr/bin/env bash
# WiFiZone Pro — installation production native Ubuntu (sans Docker)
# Usage: sudo bash deploy/ubuntu/install-native.sh
set -eu
[ -n "${BASH_VERSION:-}" ] && set -o pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Exécutez en root: sudo bash $0"
  exit 1
fi

APP_DIR="${APP_DIR:-/opt/wifizone}"
WIFIZONE_USER="${WIFIZONE_USER:-wifizone}"
WIFIZONE_GROUP="${WIFIZONE_GROUP:-$WIFIZONE_USER}"
VENV="${VENV:-$APP_DIR/venv}"
WIFI_DOMAIN="${WIFI_DOMAIN:-wifi.nigercertify.com}"
REPO_URL="${REPO_URL:-https://github.com/certify227/NigerCertify.git}"
GIT_BRANCH="${GIT_BRANCH:-cursor/wifizone-saas-django-3301}"
SKIP_DB_SETUP="${SKIP_DB_SETUP:-false}"
SKIP_REDIS_SETUP="${SKIP_REDIS_SETUP:-false}"
INSTALL_NGINX_SNIPPET="${INSTALL_NGINX_SNIPPET:-true}"

BACKEND="$APP_DIR/wifizone/backend"
DEPLOY="$APP_DIR/wifizone/deploy/production"
ENV_FILE="$DEPLOY/.env.production"
UBUNTU_DIR="$APP_DIR/wifizone/deploy/ubuntu"

echo "=== WiFiZone Pro — installation native (sans Docker) ==="

apt-get update
apt-get install -y \
  ca-certificates curl git openssl ufw fail2ban \
  python3 python3-venv python3-dev python3-pip \
  build-essential libpq-dev \
  postgresql redis-server

# Utilisateur applicatif
if ! id "$WIFIZONE_USER" >/dev/null 2>&1; then
  useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin "$WIFIZONE_USER"
fi

# Code source
mkdir -p "$APP_DIR"
if [ -d "$APP_DIR/.git" ]; then
  git -C "$APP_DIR" fetch origin
  git -C "$APP_DIR" checkout "$GIT_BRANCH"
  git -C "$APP_DIR" pull origin "$GIT_BRANCH"
elif [ -n "$REPO_URL" ]; then
  git clone --branch "$GIT_BRANCH" "$REPO_URL" "$APP_DIR"
else
  echo "Définissez REPO_URL ou clonez le dépôt dans $APP_DIR"
  exit 1
fi

chown -R "$WIFIZONE_USER:$WIFIZONE_GROUP" "$APP_DIR"

# Secrets
if [ ! -f "$ENV_FILE" ]; then
  echo "Génération des secrets pour ${WIFI_DOMAIN}..."
  WIFI_DOMAIN="$WIFI_DOMAIN" bash "$DEPLOY/scripts/generate-secrets-native.sh" "$ENV_FILE"
  chown "$WIFIZONE_USER:$WIFIZONE_GROUP" "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  echo ""
  echo "Éditez $ENV_FILE (SMTP, CREATE_SUPERUSER=true) puis relancez:"
  echo "  sudo APP_DIR=$APP_DIR bash $0"
  exit 0
fi

chmod 600 "$ENV_FILE"
chown "$WIFIZONE_USER:$WIFIZONE_GROUP" "$ENV_FILE"

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

APP_PORT="${WIFIZONE_HOST_PORT:-8004}"
GUNICORN_WORKERS="${GUNICORN_WORKERS:-2}"

# PostgreSQL
if [ "$SKIP_DB_SETUP" != "true" ]; then
  echo "Configuration PostgreSQL..."
  psql_cmd() { sudo -u postgres psql "$@"; }
  psql_cmd -tc "SELECT 1 FROM pg_roles WHERE rolname='${POSTGRES_USER}'" | grep -q 1 \
    || psql_cmd -c "CREATE USER ${POSTGRES_USER} WITH PASSWORD '${POSTGRES_PASSWORD}';"
  psql_cmd -tc "SELECT 1 FROM pg_database WHERE datname='${POSTGRES_DB}'" | grep -q 1 \
    || psql_cmd -c "CREATE DATABASE ${POSTGRES_DB} OWNER ${POSTGRES_USER};"
  psql_cmd -c "ALTER USER ${POSTGRES_USER} WITH PASSWORD '${POSTGRES_PASSWORD}';"
fi

# Redis
if [ "$SKIP_REDIS_SETUP" != "true" ] && [ -n "${REDIS_PASSWORD:-}" ]; then
  echo "Configuration Redis (requirepass)..."
  REDIS_CONF="/etc/redis/redis.conf"
  if grep -q '^# requirepass' "$REDIS_CONF"; then
    sed -i "s/^# requirepass .*/requirepass ${REDIS_PASSWORD}/" "$REDIS_CONF"
  elif grep -q '^requirepass' "$REDIS_CONF"; then
    sed -i "s/^requirepass .*/requirepass ${REDIS_PASSWORD}/" "$REDIS_CONF"
  else
    echo "requirepass ${REDIS_PASSWORD}" >> "$REDIS_CONF"
  fi
  systemctl restart redis-server
fi

systemctl enable postgresql redis-server
systemctl start postgresql redis-server

# Virtualenv Python
if [ ! -x "$VENV/bin/python" ]; then
  python3 -m venv "$VENV"
fi
"$VENV/bin/pip" install --upgrade pip wheel
"$VENV/bin/pip" install -r "$BACKEND/requirements.txt"

chown -R "$WIFIZONE_USER:$WIFIZONE_GROUP" "$VENV" "$APP_DIR"

mkdir -p "$BACKEND/media" "$BACKEND/staticfiles"
chown -R "$WIFIZONE_USER:$WIFIZONE_GROUP" "$BACKEND/media" "$BACKEND/staticfiles"

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

# Firewall (optionnel — ne bloque pas si UFW déjà configuré)
ufw allow OpenSSH || true
ufw allow 80/tcp || true
ufw allow 443/tcp || true
ufw --force enable || true

# Nginx système
if [ "$INSTALL_NGINX_SNIPPET" = "true" ] && command -v nginx >/dev/null; then
  mkdir -p /etc/nginx/snippets
  cp "$APP_DIR/wifizone/deploy/nginx-host/proxy-params.conf" /etc/nginx/snippets/proxy-params.conf
  cp "$APP_DIR/wifizone/deploy/nginx-host/wifi.nigercertify.com.conf" \
    /etc/nginx/sites-available/wifi.nigercertify.com
  ln -sf /etc/nginx/sites-available/wifi.nigercertify.com /etc/nginx/sites-enabled/wifi.nigercertify.com
  nginx -t && systemctl reload nginx
fi

echo ""
echo "=== WiFiZone Pro (natif) démarré ==="
systemctl status wifizone-web --no-pager || true
echo ""
echo "Test local: curl -I http://127.0.0.1:${APP_PORT}/"
echo "Accès: https://${WIFI_DOMAIN}"
echo ""
echo "Logs: journalctl -u wifizone-web -f"
echo "Mise à jour: bash $UBUNTU_DIR/update-native.sh"
echo ""
if [ "${CREATE_SUPERUSER:-false}" = "true" ]; then
  echo "Après vérification, désactivez CREATE_SUPERUSER=false dans $ENV_FILE"
fi
