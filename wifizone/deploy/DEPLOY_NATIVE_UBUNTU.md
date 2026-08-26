# Déploiement WiFiZone Pro — Ubuntu natif (sans Docker)

**Domaine :** [https://wifi.nigercertify.com](https://wifi.nigercertify.com)

Ce guide installe WiFiZone **directement sur Ubuntu** avec :

- **PostgreSQL** et **Redis** (paquets système)
- **Gunicorn + Uvicorn worker** (ASGI + WebSocket) via **systemd**
- **Nginx système** (déjà présent sur votre serveur)

WiFiZone écoute sur **127.0.0.1:8004** — sans conflit avec vos apps Gunicorn sur 8000–8003.

```
Internet → Nginx (443) → 127.0.0.1:8004 → Gunicorn (systemd)
                              PostgreSQL + Redis (systemd)
```

**Aucun Docker requis.**

---

## Prérequis

- Ubuntu 22.04 ou 24.04
- 2 GB RAM minimum
- DNS `wifi.nigercertify.com` → IP du serveur
- Ports 80 et 443 (Nginx)
- Branche Git : `cursor/wifizone-saas-django-3301`

---

## Installation automatique

### 1. Cloner le dépôt

```bash
sudo mkdir -p /opt/wifizone
sudo git clone https://github.com/certify227/NigerCertify.git /opt/wifizone
cd /opt/wifizone
sudo git checkout cursor/wifizone-saas-django-3301
```

Si Git signale `dubious ownership` :

```bash
sudo git config --global --add safe.directory /opt/wifizone
sudo chown -R adminsys0:adminsys0 /opt/wifizone
```

### 2. Premier passage (génération des secrets)

```bash
cd /opt/wifizone/wifizone
sudo bash deploy/ubuntu/install-native.sh
```

Le script génère `deploy/production/.env.production` avec des mots de passe aléatoires.

**Notez le mot de passe admin** affiché dans le terminal.

### 3. Éditer l'environnement

```bash
sudo nano /opt/wifizone/wifizone/deploy/production/.env.production
```

Vérifiez :

```env
CREATE_SUPERUSER=true
WIFIZONE_HOST_PORT=8004
APP_PORT=8004
ASGI_SERVER=gunicorn
```

Complétez `EMAIL_*` si vous utilisez le reset mot de passe par email.

### 4. Second passage (installation complète)

```bash
sudo bash /opt/wifizone/wifizone/deploy/ubuntu/install-native.sh
```

### 5. Vérification

```bash
curl -I http://127.0.0.1:8004/
sudo systemctl status wifizone-web wifizone-celery-worker wifizone-celery-beat
```

Réponse attendue : HTTP 200 ou 302.

---

## Serveur multi-apps (votre cas : ports 8000–8003 déjà utilisés)

Si PostgreSQL ou Redis sont **déjà utilisés** par d'autres applications :

```bash
sudo SKIP_DB_SETUP=true SKIP_REDIS_SETUP=true \
  WIFIZONE_USER=adminsys0 WIFIZONE_GROUP=adminsys0 \
  bash /opt/wifizone/wifizone/deploy/ubuntu/install-native.sh
```

Adaptez ensuite `.env.production` :

```env
DATABASE_URL=postgres://USER:PASS@127.0.0.1:5432/wifizone
CELERY_BROKER_URL=redis://:MOT_DE_PASSE@127.0.0.1:6379/0
CELERY_RESULT_BACKEND=redis://:MOT_DE_PASSE@127.0.0.1:6379/0
CHANNEL_LAYER_URL=redis://:MOT_DE_PASSE@127.0.0.1:6379/1
WIFIZONE_HOST_PORT=8004
APP_PORT=8004
```

Créez la base manuellement si besoin :

```bash
sudo -u postgres psql -c "CREATE USER wifizone WITH PASSWORD '...';"
sudo -u postgres psql -c "CREATE DATABASE wifizone OWNER wifizone;"
```

---

## Services systemd

| Service | Rôle |
|---------|------|
| `wifizone-web` | Gunicorn ASGI sur 127.0.0.1:8004 |
| `wifizone-celery-worker` | Tâches asynchrones |
| `wifizone-celery-beat` | Planificateur Celery |

```bash
# Statut
sudo systemctl status wifizone-web

# Logs
sudo journalctl -u wifizone-web -f

# Redémarrage
sudo systemctl restart wifizone-web wifizone-celery-worker wifizone-celery-beat
```

---

## Nginx et SSL

Si Nginx n'a pas été configuré par l'installateur :

```bash
sudo cp /opt/wifizone/wifizone/deploy/nginx-host/proxy-params.conf /etc/nginx/snippets/proxy-params.conf
sudo cp /opt/wifizone/wifizone/deploy/nginx-host/wifi.nigercertify.com.conf \
  /etc/nginx/sites-available/wifi.nigercertify.com
sudo ln -sf /etc/nginx/sites-available/wifi.nigercertify.com /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

Certificat Let's Encrypt (si pas déjà en place) :

```bash
sudo certbot --nginx -d wifi.nigercertify.com -d www.wifi.nigercertify.com
```

---

## Mise à jour

```bash
bash /opt/wifizone/wifizone/deploy/ubuntu/update-native.sh
```

Ou manuellement :

```bash
cd /opt/wifizone && git pull
sudo -u wifizone env APP_DIR=/opt/wifizone bash wifizone/deploy/ubuntu/bootstrap-native.sh
sudo systemctl restart wifizone-web wifizone-celery-worker wifizone-celery-beat
```

---

## Génération manuelle des secrets (natif)

```bash
cd /opt/wifizone/wifizone/deploy/production
./scripts/generate-secrets-native.sh .env.production
```

Différence avec la version Docker : les URLs pointent vers `127.0.0.1` (PostgreSQL/Redis système), pas vers `db`/`redis`.

---

## Admin Django

Après premier déploiement avec `CREATE_SUPERUSER=true` :

`https://wifi.nigercertify.com/admin/`

Puis dans `.env.production` :

```env
CREATE_SUPERUSER=false
```

---

## Sauvegarde PostgreSQL

```bash
sudo -u postgres pg_dump -U wifizone wifizone > backup_$(date +%F).sql
```

---

## Comparaison Docker vs natif

| | Docker (`DEPLOY_HOST_NGINX.md`) | Natif (ce guide) |
|--|--------------------------------|------------------|
| PostgreSQL | Conteneur | Paquet `postgresql` |
| Redis | Conteneur | Paquet `redis-server` |
| App | Conteneur Gunicorn | systemd + venv Python |
| Port app | 127.0.0.1:8004 | 127.0.0.1:8004 |
| Nginx | Système | Système |

---

## Dépannage

| Problème | Solution |
|----------|----------|
| `502 Bad Gateway` | `journalctl -u wifizone-web -n 50` — migrations ou secrets |
| Port 8004 occupé | Changer `WIFIZONE_HOST_PORT` + upstream Nginx |
| Redis auth failed | Vérifier `REDIS_PASSWORD` et `requirepass` dans `/etc/redis/redis.conf` |
| WebSocket | Nginx `/ws/` + `CHANNEL_LAYER_URL` correct |
| `ImproperlyConfigured` | `FERNET_KEY`, `DJANGO_SECRET_KEY`, `DATABASE_URL` |

---

## Fichiers utiles

| Fichier | Description |
|---------|-------------|
| `deploy/ubuntu/install-native.sh` | Installation complète |
| `deploy/ubuntu/bootstrap-native.sh` | Migrations + static |
| `deploy/ubuntu/update-native.sh` | Mise à jour |
| `deploy/production/scripts/generate-secrets-native.sh` | Secrets pour mode natif |
| `deploy/ubuntu/systemd/*.service` | Modèles systemd |
