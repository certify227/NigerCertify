# Déploiement WiFiZone Pro sur Ubuntu (production sécurisée)

**Domaine production :** [https://wifi.nigercertify.com](https://wifi.nigercertify.com)

Guide pour déployer WiFiZone Pro sur un serveur **Ubuntu 22.04 / 24.04** avec Docker, Nginx, TLS et durcissement sécurité.

## Prérequis

- Serveur Ubuntu avec **2 GB RAM** minimum (4 GB recommandé)
- Nom de domaine pointant vers le serveur (DNS A record)
- Ports **80** et **443** ouverts (SSH 22 pour administration)

## Installation rapide

```bash
# Cloner le projet
sudo mkdir -p /opt/wifizone
sudo git clone https://github.com/certify227/NigerCertify.git /opt/wifizone
cd /opt/wifizone/wifizone

# Installation automatique (Docker, UFW, Fail2ban)
sudo bash deploy/ubuntu/install.sh
```

Le script génère `deploy/production/.env.production` avec des secrets aléatoires.

**Éditez** ce fichier avant le second passage :

```bash
sudo nano /opt/wifizone/wifizone/deploy/production/.env.production
```

Modifiez au minimum :

- `EMAIL_*` — SMTP pour reset mot de passe (ex. `smtp.nigercertify.com`)
- `CREATE_SUPERUSER=true` uniquement au **premier** déploiement

Le domaine est déjà configuré : `wifi.nigercertify.com`

Relancez l’installation :

```bash
sudo APP_DIR=/opt/wifizone bash deploy/ubuntu/install.sh
```

## Certificat SSL (Let's Encrypt)

```bash
cd /opt/wifizone/wifizone/deploy/production

docker compose -f docker-compose.prod.yml run --rm certbot certonly \
  --webroot -w /var/www/certbot \
  -d wifi.nigercertify.com -d www.wifi.nigercertify.com \
  --email admin@nigercertify.com --agree-tos --no-eff-email

./scripts/enable-ssl.sh
```

## Commandes utiles

```bash
cd /opt/wifizone/wifizone/deploy/production

# Statut
docker compose -f docker-compose.prod.yml ps

# Logs
docker compose -f docker-compose.prod.yml logs -f web nginx

# Mise à jour
cd /opt/wifizone && sudo git pull
cd wifizone/deploy/production
docker compose -f docker-compose.prod.yml build --pull
docker compose -f docker-compose.prod.yml up -d

# Sauvegarde PostgreSQL
docker compose -f docker-compose.prod.yml exec -T db \
  pg_dump -U wifizone wifizone > backup_$(date +%F).sql
```

## Sécurité intégrée

| Mesure | Détail |
|--------|--------|
| **Secrets** | `DJANGO_SECRET_KEY`, `FERNET_KEY`, mots de passe DB/Redis générés aléatoirement |
| **TLS** | TLS 1.2/1.3, HSTS, redirection HTTPS |
| **Headers** | CSP, X-Frame-Options, nosniff, Referrer-Policy |
| **Cookies** | Secure + HttpOnly en production |
| **CSRF** | Origines explicites (`CSRF_TRUSTED_ORIGINS`) |
| **Réseau** | PostgreSQL et Redis **non exposés** sur l'hôte |
| **Redis** | Mot de passe obligatoire |
| **Nginx** | Rate limiting login/API, `server_tokens off` |
| **Docker** | `no-new-privileges`, conteneurs sans ports DB/Redis publics |
| **API** | Throttling renforcé, JWT durée réduite (4h / 7j) |
| **Admin** | Chemin personnalisable via `DJANGO_ADMIN_URL` |
| **API docs** | Désactivées par défaut (`ENABLE_API_DOCS=false`) |
| **UFW** | 22, 80, 443 uniquement |
| **Fail2ban** | Protection SSH |

## Variables d'environnement importantes

Voir `deploy/production/.env.production.example`.

Génération manuelle des secrets :

```bash
cd wifizone/deploy/production
./scripts/generate-secrets.sh .env.production
```

## Admin Django

Après premier déploiement avec `CREATE_SUPERUSER=true`, connectez-vous à :

`https://wifi.nigercertify.com/admin/` (ou chemin `DJANGO_ADMIN_URL`)

**Changez le mot de passe admin** immédiatement et désactivez `CREATE_SUPERUSER`.

## MikroTik production

- `MIKROTIK_MOCK_MODE=false` (défaut en production)
- Ouvrez le port API **8728** depuis le serveur vers vos routeurs (pas depuis Internet vers le serveur)

## Dépannage

| Problème | Solution |
|----------|----------|
| `ImproperlyConfigured` au démarrage | Vérifiez `FERNET_KEY`, `CSRF_TRUSTED_ORIGINS`, `DJANGO_SECRET_KEY` |
| 502 Bad Gateway | `docker compose logs web` — migrations ou secrets |
| WebSocket | Vérifiez Nginx `/ws/` et `CSRF_TRUSTED_ORIGINS` |
| Certificat SSL | DNS propagé ? Challenge `/.well-known/acme-challenge/` accessible |

## Développement local

Utilisez le fichier standard (non production) :

```bash
cd wifizone
docker compose up --build
```

Ne **jamais** utiliser `docker-compose.yml` de dev sur un serveur public.
