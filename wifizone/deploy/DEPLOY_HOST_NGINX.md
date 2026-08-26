# Déploiement avec Nginx système (ports 8000-8003 déjà utilisés)

Ce mode est fait pour un serveur Ubuntu où **Nginx** et **Gunicorn** gèrent déjà d'autres applications sur **8000, 8001, 8002, 8003**.

WiFiZone Pro utilise le port **8004** en local (`127.0.0.1`) — **aucun conflit** avec vos apps existantes.

## Architecture

```
Internet → Nginx (système, 443) → 127.0.0.1:8004 → Docker (Gunicorn+Uvicorn)
                                              PostgreSQL + Redis (Docker, internes)
```

WiFiZone utilise **Gunicorn avec worker Uvicorn** (ASGI) pour supporter le **WebSocket** du tableau de bord (`/ws/dashboard/`).

---

## Étape 1 — Prérequis

- Docker installé
- Nginx + Certbot déjà configurés sur le serveur
- DNS `wifi.nigercertify.com` → IP du serveur
- Code sur la branche **`cursor/wifizone-saas-django-3301`** (fichier `docker-compose.host-nginx.yml`)

```bash
cd /opt/wifizone
git fetch origin
git checkout cursor/wifizone-saas-django-3301
git pull origin cursor/wifizone-saas-django-3301
```

Vérification :

```bash
bash wifizone/deploy/production/check-deploy.sh
```

---

## Étape 2 — Code et secrets

```bash
cd /opt/wifizone/wifizone/deploy/production

# Si .env.production n'existe pas encore
./scripts/generate-secrets.sh .env.production
sudo nano .env.production
```

Ajoutez / vérifiez :

```env
WIFIZONE_HOST_PORT=8004
ASGI_SERVER=gunicorn
CREATE_SUPERUSER=true   # premier déploiement seulement
```

---

## Étape 3 — Lancer Docker (sans Nginx Docker)

```bash
cd /opt/wifizone/wifizone/deploy/production

bash ./scripts/compose-up.sh build --pull
bash ./scripts/compose-up.sh up -d
bash ./scripts/compose-up.sh ps
```

Le script `compose-up.sh` valide `.env.production`, crée le lien `.env` et passe `--env-file` à Docker Compose (évite l’erreur `POSTGRES_PASSWORD requis`).

Si Git refuse l’accès au dépôt (`dubious ownership`) :

```bash
sudo git config --global --add safe.directory /opt/wifizone
sudo chown -R adminsys0:adminsys0 /opt/wifizone
```

Vérification locale :

```bash
curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8004/
# doit retourner 200
```

**Ne pas** utiliser `docker-compose.prod.yml` (il inclut un Nginx Docker sur 80/443).

---

## Étape 4 — Configurer Nginx système

```bash
# Snippet proxy (si absent)
sudo cp /opt/wifizone/wifizone/deploy/nginx-host/proxy-params.conf \
  /etc/nginx/snippets/proxy-params.conf

# Site WiFiZone
sudo cp /opt/wifizone/wifizone/deploy/nginx-host/wifi.nigercertify.com.conf \
  /etc/nginx/sites-available/wifi.nigercertify.com

sudo ln -sf /etc/nginx/sites-available/wifi.nigercertify.com /etc/nginx/sites-enabled/

sudo nginx -t
sudo systemctl reload nginx
```

### SSL (si pas encore fait pour ce sous-domaine)

```bash
sudo certbot certonly --nginx -d wifi.nigercertify.com -d www.wifi.nigercertify.com
sudo nginx -t && sudo systemctl reload nginx
```

Adaptez les chemins `ssl_certificate` dans le fichier Nginx si votre Certbot utilise une autre structure.

---

## Étape 5 — Accès

- Application : https://wifi.nigercertify.com
- Admin : https://wifi.nigercertify.com/admin/

Puis `CREATE_SUPERUSER=false` dans `.env.production` et :

```bash
docker compose -f docker-compose.host-nginx.yml up -d
```

---

## Ports sur votre serveur (résumé)

| Port | Usage |
|------|--------|
| 8000 | Votre app existante |
| 8001 | Votre app existante |
| 8002 | Votre app existante |
| 8003 | Votre app existante |
| **8004** | **WiFiZone Pro** (127.0.0.1 uniquement) |
| 80 / 443 | Nginx système (partagé) |

Pour changer le port WiFiZone : `WIFIZONE_HOST_PORT=8005` dans `.env.production` + adapter `upstream` dans le fichier Nginx.

---

## Commandes utiles

```bash
cd /opt/wifizone/wifizone/deploy/production

# Logs
docker compose -f docker-compose.host-nginx.yml logs -f web

# Redémarrage
docker compose -f docker-compose.host-nginx.yml restart web

# Mise à jour
cd /opt/wifizone && git pull
cd wifizone/deploy/production
docker compose -f docker-compose.host-nginx.yml build --pull
docker compose -f docker-compose.host-nginx.yml up -d
```

---

## Dépannage

| Problème | Solution |
|----------|----------|
| 502 sur le domaine | `curl http://127.0.0.1:8004/` — si KO, voir `docker compose logs web` |
| Port 8004 occupé | Changer `WIFIZONE_HOST_PORT` (ex. 8005) + Nginx upstream |
| WebSocket KO | Vérifier le bloc `location /ws/` dans Nginx |
| Conflit avec prod.yml | Ne lancez pas le stack avec Nginx Docker en parallèle |
