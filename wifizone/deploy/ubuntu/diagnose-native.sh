#!/usr/bin/env bash
# Diagnostic WiFiZone Pro — déploiement natif (sans Docker)
set -eu
[ -n "${BASH_VERSION:-}" ] && set -o pipefail

APP_DIR="${APP_DIR:-/opt/wifizone}"
DEPLOY="$APP_DIR/wifizone/deploy/production"
ENV_FILE="$DEPLOY/.env.production"
DOMAIN="${WIFI_DOMAIN:-wifi.nigercertify.com}"
APP_PORT="${WIFIZONE_HOST_PORT:-8004}"
NGINX_SITE="/etc/nginx/sites-available/${DOMAIN}"
NGINX_ENABLED="/etc/nginx/sites-enabled/${DOMAIN}"

ok() { echo "  ✅ $1"; }
warn() { echo "  ⚠️  $1"; }
fail() { echo "  ❌ $1"; }

echo "=== WiFiZone — diagnostic déploiement natif ==="
echo "Date: $(date -Iseconds)"
echo "Hôte: $(hostname)"
echo ""

echo "--- 1. Code source ---"
if [ -d "$APP_DIR/.git" ]; then
  ok "Dépôt git: $APP_DIR"
  if git -C "$APP_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "     Branche: $(git -C "$APP_DIR" branch --show-current 2>/dev/null || echo '?')"
    echo "     Commit:  $(git -C "$APP_DIR" rev-parse --short HEAD 2>/dev/null || echo '?')"
  else
    fail "Git dubious ownership — exécutez:"
    echo "       sudo git config --global --add safe.directory $APP_DIR"
    echo "       sudo chown -R \$(whoami):\$(whoami) $APP_DIR"
  fi
else
  fail "Pas de dépôt git dans $APP_DIR"
fi

if [ -f "$APP_DIR/wifizone/deploy/ubuntu/install-native.sh" ]; then
  ok "Scripts natifs présents"
else
  fail "Scripts natifs absents — git pull sur cursor/wifizone-saas-django-3301"
fi

echo ""
echo "--- 2. Secrets (.env.production) ---"
if [ -f "$ENV_FILE" ]; then
  ok "Fichier: $ENV_FILE"
  for key in POSTGRES_PASSWORD REDIS_PASSWORD DJANGO_SECRET_KEY FERNET_KEY DATABASE_URL; do
    val="$(grep -E "^${key}=" "$ENV_FILE" | head -1 | cut -d= -f2- || true)"
    if [ -n "$val" ]; then
      ok "$key défini"
    else
      fail "$key VIDE — regénérez: ./scripts/generate-secrets-native.sh .env.production"
    fi
  done
else
  fail ".env.production manquant dans $DEPLOY"
fi

echo ""
echo "--- 3. Backend (port ${APP_PORT}) ---"
if ss -tlnp 2>/dev/null | grep -q ":${APP_PORT} "; then
  ok "Port ${APP_PORT} en écoute"
  ss -tlnp 2>/dev/null | grep ":${APP_PORT} " || true
else
  fail "Rien n'écoute sur 127.0.0.1:${APP_PORT}"
fi

if systemctl is-active wifizone-web >/dev/null 2>&1; then
  ok "Service wifizone-web actif"
elif systemctl list-unit-files wifizone-web.service >/dev/null 2>&1; then
  fail "wifizone-web installé mais inactif — journalctl -u wifizone-web -n 30"
else
  warn "Service systemd wifizone-web absent — lancez install-native.sh"
fi

if curl -sf -o /dev/null -w "" --max-time 5 "http://127.0.0.1:${APP_PORT}/" 2>/dev/null; then
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${APP_PORT}/")"
  ok "HTTP local ${APP_PORT}: ${code}"
else
  fail "curl http://127.0.0.1:${APP_PORT}/ échoue"
fi

echo ""
echo "--- 4. PostgreSQL / Redis ---"
if systemctl is-active postgresql >/dev/null 2>&1; then
  ok "PostgreSQL actif"
else
  warn "PostgreSQL inactif ou absent"
fi
if systemctl is-active redis-server >/dev/null 2>&1; then
  ok "Redis actif"
else
  warn "Redis inactif ou absent"
fi

echo ""
echo "--- 5. Nginx ---"
if command -v nginx >/dev/null; then
  ok "Nginx installé: $(nginx -v 2>&1)"
else
  fail "Nginx non installé"
fi

if [ -f "$NGINX_SITE" ]; then
  ok "Config: $NGINX_SITE"
else
  fail "Config Nginx absente pour $DOMAIN"
fi

if [ -L "$NGINX_ENABLED" ] || [ -f "$NGINX_ENABLED" ]; then
  ok "Site activé: sites-enabled/$DOMAIN"
else
  fail "Site NON activé — ln -sf $NGINX_SITE $NGINX_ENABLED"
fi

if [ -f /etc/nginx/snippets/proxy-params.conf ]; then
  ok "Snippet proxy-params.conf"
else
  fail "Snippet /etc/nginx/snippets/proxy-params.conf manquant"
fi

if nginx -t >/dev/null 2>&1; then
  ok "nginx -t OK"
else
  fail "nginx -t en erreur"
  sudo nginx -t 2>&1 | sed 's/^/     /' || true
fi

echo ""
echo "--- 6. SSL (${DOMAIN}) ---"
CERT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
if [ -f "$CERT" ]; then
  ok "Certificat dédié: $CERT"
else
  fail "Pas de certificat pour ${DOMAIN}"
  if [ -f /etc/letsencrypt/live/nigercertify.com/fullchain.pem ]; then
    warn "Certificat nigercertify.com existe — ajoutez le sous-domaine:"
    echo "       sudo certbot certonly --nginx -d ${DOMAIN} -d www.${DOMAIN}"
    echo "       ou: sudo certbot certonly --expand -d nigercertify.com -d www.nigercertify.com -d ${DOMAIN}"
  fi
fi

echo ""
echo "--- 7. Docker (optionnel) ---"
if docker ps --format '{{.Names}}' 2>/dev/null | grep -qi wifizone; then
  warn "Conteneurs WiFiZone Docker détectés (conflit possible avec natif):"
  docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null | grep -i wifizone || true
else
  ok "Pas de conteneur WiFiZone Docker actif"
fi

echo ""
echo "--- 8. Test externe ---"
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 "http://${DOMAIN}/" 2>/dev/null || echo '000')"
echo "  HTTP ${DOMAIN}: ${code}"
if [ "$code" = "404" ]; then
  fail "404 = Nginx ne route pas vers WiFiZone (site non activé ou mauvais server_name)"
elif [ "$code" = "301" ] || [ "$code" = "302" ]; then
  ok "Redirection HTTP OK"
elif [ "$code" = "200" ]; then
  ok "Site accessible en HTTP"
fi

echo ""
echo "=== Fin diagnostic ==="
echo "Correction automatique: sudo bash $APP_DIR/wifizone/deploy/ubuntu/fix-deploy-native.sh"
