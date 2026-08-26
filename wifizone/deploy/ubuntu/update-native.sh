#!/usr/bin/env bash
# Mise à jour WiFiZone Pro (natif, sans Docker)
set -eu
[ -n "${BASH_VERSION:-}" ] && set -o pipefail

APP_DIR="${APP_DIR:-/opt/wifizone}"
WIFIZONE_USER="${WIFIZONE_USER:-wifizone}"
VENV="${VENV:-$APP_DIR/venv}"
ENV_FILE="${ENV_FILE:-$APP_DIR/wifizone/deploy/production/.env.production}"

cd "$APP_DIR"
git pull

sudo -u "$WIFIZONE_USER" env APP_DIR="$APP_DIR" VENV="$VENV" ENV_FILE="$ENV_FILE" \
  bash "$APP_DIR/wifizone/deploy/ubuntu/bootstrap-native.sh"

sudo systemctl restart wifizone-web wifizone-celery-worker wifizone-celery-beat
sudo systemctl status wifizone-web --no-pager

echo "Mise à jour terminée."
