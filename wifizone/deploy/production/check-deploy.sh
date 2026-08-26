#!/usr/bin/env bash
# Vérifie le dépôt et la présence des fichiers de déploiement host-nginx.
set -eu
[ -n "${BASH_VERSION:-}" ] && set -o pipefail

echo "=== WiFiZone — diagnostic déploiement ==="

# Chemins possibles
CANDIDATES=(
  "/opt/wifizone/wifizone/deploy/production"
  "/opt/wifizone/deploy/production"
  "$(cd "$(dirname "$0")" && pwd)"
)

DEPLOY=""
for d in "$CANDIDATES"; do
  if [ -f "$d/docker-compose.host-nginx.yml" ]; then
    DEPLOY="$d"
    break
  fi
done

if [ -z "$DEPLOY" ]; then
  echo "❌ docker-compose.host-nginx.yml introuvable."
  echo ""
  echo "Chemins testés :"
  for d in "$CANDIDATES"; do echo "  - $d"; done
  echo ""
  REPO_ROOT="$(cd "$(dirname "$0")/../../.." 2>/dev/null && pwd || true)"
  if [ -d "$REPO_ROOT/.git" ]; then
    echo "Dépôt git : $REPO_ROOT"
    echo "Branche actuelle : $(git -C "$REPO_ROOT" branch --show-current)"
    echo ""
    echo "Solution — basculer sur la branche WiFiZone et tirer :"
    echo "  cd $REPO_ROOT"
    echo "  git fetch origin"
    echo "  git checkout cursor/wifizone-saas-django-3301"
    echo "  git pull origin cursor/wifizone-saas-django-3301"
  else
    echo "Pas de dépôt git détecté. Clonez :"
    echo "  sudo git clone https://github.com/certify227/NigerCertify.git /opt/wifizone"
    echo "  cd /opt/wifizone && git checkout cursor/wifizone-saas-django-3301"
  fi
  exit 1
fi

echo "✅ Fichier trouvé : $DEPLOY/docker-compose.host-nginx.yml"

if [ -f "$DEPLOY/.env.production" ]; then
  missing=0
  for key in POSTGRES_PASSWORD REDIS_PASSWORD DJANGO_SECRET_KEY FERNET_KEY DATABASE_URL; do
    val="$(grep -E "^${key}=" "$DEPLOY/.env.production" | head -1 | cut -d= -f2-)"
    if [ -z "$val" ]; then
      echo "❌ Variable vide : $key"
      missing=1
    fi
  done
  if [ "$missing" -eq 0 ]; then
    echo "✅ .env.production — secrets présents"
  else
    echo "   Regénérez : cd $DEPLOY && mv .env.production .env.production.bak && ./scripts/generate-secrets.sh .env.production"
  fi
else
  echo "❌ .env.production manquant — ./scripts/generate-secrets.sh .env.production"
fi

echo ""
echo "Pour déployer :"
echo "  cd $DEPLOY"
echo "  bash ./scripts/compose-up.sh up -d --build"
