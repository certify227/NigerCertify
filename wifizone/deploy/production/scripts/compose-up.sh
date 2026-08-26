#!/usr/bin/env bash
set -eu
[ -n "${BASH_VERSION:-}" ] && set -o pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ ! -f .env.production ]; then
  echo "Fichier .env.production manquant. Lancez : ./scripts/generate-secrets.sh .env.production"
  exit 1
fi

for key in POSTGRES_PASSWORD REDIS_PASSWORD DJANGO_SECRET_KEY FERNET_KEY DATABASE_URL; do
  val="$(grep -E "^${key}=" .env.production | head -1 | cut -d= -f2-)"
  if [ -z "$val" ]; then
    echo "Variable vide dans .env.production : $key"
    echo "Regénérez les secrets : mv .env.production .env.production.bak && ./scripts/generate-secrets.sh .env.production"
    exit 1
  fi
done

ln -sf .env.production .env

if [ -n "${DOCKER_COMPOSE:-}" ]; then
  DC=($DOCKER_COMPOSE)
elif docker compose version >/dev/null 2>&1; then
  DC=(docker compose)
elif sudo docker compose version >/dev/null 2>&1; then
  DC=(sudo docker compose)
else
  echo "docker compose introuvable. Installez Docker ou définissez DOCKER_COMPOSE."
  exit 1
fi

exec "${DC[@]}" --env-file .env.production -f docker-compose.host-nginx.yml "$@"
