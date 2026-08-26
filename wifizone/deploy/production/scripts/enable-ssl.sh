#!/usr/bin/env bash
# Active HTTPS après obtention du certificat Let's Encrypt.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPLOY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$DEPLOY_DIR"

if [ ! -f .env.production ]; then
  echo "Fichier .env.production manquant."
  exit 1
fi

set -a
source .env.production
set +a

HOST="${NGINX_HOST:?NGINX_HOST requis dans .env.production}"

if ! docker compose -f docker-compose.prod.yml exec -T nginx test -f "/etc/letsencrypt/live/${HOST}/fullchain.pem"; then
  echo "Certificat absent. Exécutez d'abord:"
  echo "  docker compose -f docker-compose.prod.yml run --rm certbot certonly --webroot -w /var/www/certbot -d ${HOST} -d www.${HOST} --email admin@${HOST} --agree-tos --no-eff-email"
  exit 1
fi

sed "s/__NGINX_HOST__/${HOST}/g" nginx/conf.d/wifizone-ssl.conf.template > nginx/conf.d/wifizone-ssl.conf

docker compose -f docker-compose.prod.yml exec nginx nginx -t
docker compose -f docker-compose.prod.yml exec nginx nginx -s reload

echo "HTTPS activé pour ${HOST}"
