#!/usr/bin/env bash
# WiFiZone Pro — installation production sur Ubuntu 22.04/24.04
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Exécutez ce script en root: sudo $0"
  exit 1
fi

APP_DIR="${APP_DIR:-/opt/wifizone}"
REPO_URL="${REPO_URL:-}"
WIFI_DOMAIN="${WIFI_DOMAIN:-wifi.nigercertify.com}"

echo "=== WiFiZone Pro — déploiement production ==="

# Paquets système
apt-get update
apt-get install -y ca-certificates curl gnupg ufw fail2ban openssl

# Docker (officiel)
if ! command -v docker >/dev/null; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
fi

systemctl enable docker
systemctl start docker

# Firewall
ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

# Fail2ban basique SSH
cat > /etc/fail2ban/jail.d/wifizone.local <<'EOF'
[sshd]
enabled = true
maxretry = 5
bantime = 3600
EOF
systemctl enable fail2ban
systemctl restart fail2ban || true

# Code source
if [ -n "$REPO_URL" ]; then
  mkdir -p "$APP_DIR"
  if [ -d "$APP_DIR/.git" ]; then
    cd "$APP_DIR" && git pull
  else
    git clone "$REPO_URL" "$APP_DIR"
  fi
else
  echo "Copiez le dossier wifizone dans $APP_DIR (ou définissez REPO_URL)."
  mkdir -p "$APP_DIR"
fi

DEPLOY="$APP_DIR/wifizone/deploy/production"
if [ ! -d "$DEPLOY" ]; then
  echo "Répertoire deploy introuvable: $DEPLOY"
  exit 1
fi

cd "$DEPLOY"

if [ ! -f .env.production ]; then
  echo "Génération des secrets pour ${WIFI_DOMAIN}..."
  WIFI_DOMAIN="$WIFI_DOMAIN" bash scripts/generate-secrets.sh .env.production
  echo "Éditez .env.production (domaine, email SMTP) puis relancez:"
  echo "  sudo APP_DIR=$APP_DIR $0"
  exit 0
fi

chmod 600 .env.production
chmod +x scripts/*.sh
chmod +x ../ubuntu/*.sh 2>/dev/null || true

docker compose -f docker-compose.prod.yml build --pull
docker compose -f docker-compose.prod.yml up -d

echo ""
echo "=== Services démarrés ==="
docker compose -f docker-compose.prod.yml ps
echo ""
echo "1. Pointez votre domaine vers ce serveur (DNS A record)"
echo "2. Certificat SSL:"
echo "   cd $DEPLOY"
echo "   docker compose -f docker-compose.prod.yml run --rm certbot certonly --webroot -w /var/www/certbot -d ${WIFI_DOMAIN} -d www.${WIFI_DOMAIN} --email admin@nigercertify.com --agree-tos --no-eff-email"
echo "3. Activez HTTPS: ./scripts/enable-ssl.sh"
echo "4. Accès: https://${WIFI_DOMAIN}"
echo ""
echo "Logs: docker compose -f docker-compose.prod.yml logs -f web"
