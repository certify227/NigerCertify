# WiFiZone Pro

Plateforme SaaS Django pour opérateurs de zones WiFi (hotspot MikroTik), inspirée de Mikhmon.

## Fonctionnalités

- **Multi-tenant** : chaque propriétaire de zone WiFi a son compte et ses données isolées
- **Abonnements** : forfaits Starter, Pro, Enterprise avec limites (routeurs, vouchers/mois, profils)
- **Routeurs MikroTik** : connexion API (port 8728), test de connexion, sync profils depuis le routeur
- **Profils hotspot** : durée, limite data, prix de vente
- **Vouchers** : génération en lot, QR codes (scan login), sync MikroTik, impression, export CSV
- **Monitoring** : utilisateurs actifs en temps réel sur tous les routeurs
- **Rapports** : ventes par profil, graphique 7 jours sur le tableau de bord
- **Sécurité** : réinitialisation mot de passe par email, chiffrement identifiants routeur
- **Interface responsive** : Bootstrap 5, mobile-friendly
- **Enterprise** : équipe multi-utilisateurs, commissions, points de vente, invitations email
- **Core** : branding white-label, audit, webhooks, notifications, onboarding, carte WiFi publique
- **Support** : tickets d'assistance
- **Portefeuilles clients** : recharge manuelle (sans passerelle paiement)
- **Fidélité** : programme points par voucher
- **2FA** : TOTP (Google Authenticator)
- **Rapports** : avancés + export PDF
- **Import CSV** : utilisateurs MikroTik
- **API OpenAPI** : `/api/docs/` — POS, wallets, notifications, support, dashboard live
- **App mobile** : Expo (`wifizone/mobile/`) — JWT + stats live
- **Celery** : health routeurs, alertes abonnement (Redis)
- **WebSocket** : dashboard live (`/ws/dashboard/`) via Daphne + Channels
- **SNMP** : monitoring routeurs (mock ou snmpget)
- **RADIUS** : export FreeRADIUS radcheck
- **Marketplace** : templates login partagés entre opérateurs
- **Prévisions** : analytics prédictifs 7 jours
- **SMS** : passerelle HTTP ou console (`SMS_BACKEND=http`)
- **Cyber café** : délai timer sur page login

## Déploiement production (Ubuntu)

**Guide complet :** [deploy/DEPLOY_UBUNTU.md](deploy/DEPLOY_UBUNTU.md)

```bash
sudo git clone https://github.com/certify227/NigerCertify.git /opt/wifizone
cd /opt/wifizone/wifizone
sudo bash deploy/ubuntu/install.sh
```

Pack production : Docker sécurisé, Nginx, TLS Let's Encrypt, UFW, secrets générés, durcissement Django.

## Déploiement rapide (Docker)

```bash
cd wifizone
cp .env.example .env
docker compose up --build
```

Application : **http://localhost:8080**

Compte admin par défaut : `admin` / `admin1234`

## Développement local

```bash
cd wifizone/backend
pip install -r requirements.txt
export DJANGO_DEBUG=true
export MIKROTIK_MOCK_MODE=true
python manage.py migrate
python manage.py seed_plans
python manage.py createsuperuser
python manage.py runserver 8080
```

## Configuration MikroTik

1. Activer le service API sur le routeur (port 8728)
2. Créer un utilisateur API avec droits hotspot
3. Dans WiFiZone : Ajouter routeur → tester la connexion
4. Créer des profils correspondant aux profils MikroTik (`1hour`, `1day`, etc.)
5. Générer des vouchers (sync automatique sur le routeur)

## Mode démo

Sans routeur réel, définir `MIKROTIK_MOCK_MODE=true` pour simuler les réponses API.

## Abonnements

L'activation des forfaits est simulée (pas de Stripe / Mobile Money intégré).

## Structure

```
wifizone/backend/
  accounts/    — utilisateurs opérateurs
  billing/     — forfaits et abonnements
  routers/     — routeurs MikroTik + service API
  hotspots/    — profils, vouchers, rapports
  dashboard/   — landing + tableau de bord
  api/         — REST JWT + OpenAPI
  core/        — branding, audit, webhooks, notifications
  support/     — tickets assistance
wifizone/mobile/ — app Expo (optionnel)
```

## API REST (app mobile)

Base URL : `/api/v1/`

### Authentification JWT

```bash
# Obtenir un token
curl -X POST http://localhost:8080/api/v1/auth/token/ \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin1234"}'

# Utiliser le token
curl http://localhost:8080/api/v1/dashboard/ \
  -H "Authorization: Bearer <access_token>"
```

### Endpoints principaux

| Endpoint | Description |
|----------|-------------|
| `POST /api/v1/auth/token/` | Login JWT |
| `POST /api/v1/auth/token/refresh/` | Refresh token |
| `GET /api/v1/me/` | Profil + abonnement |
| `GET /api/v1/dashboard/` | Stats tableau de bord |
| `GET/POST /api/v1/routers/` | Routeurs MikroTik |
| `POST /api/v1/routers/{id}/test_connection/` | Test API |
| `GET/POST /api/v1/profiles/` | Profils hotspot |
| `GET /api/v1/vouchers/` | Liste vouchers |
| `POST /api/v1/vouchers/generate/` | Générer vouchers |
| `GET /api/v1/batches/` | Lots de vouchers |
| `GET /api/v1/batches/{id}/qr_codes/` | QR codes base64 |
| `GET /api/v1/active-users/` | Connexions actives |
| `GET/POST /api/v1/login-templates/` | Templates login |
| `GET /api/v1/login-templates/{id}/download/` | Télécharger login.html |
| `GET/POST /api/v1/team/` | Employés (Enterprise) |

Les employés Enterprise accèdent aux données de leur opérateur via le même token JWT.

## Multi-utilisateurs (Enterprise)

- Forfait **Enterprise** : jusqu'à 10 employés
- Rôles : **Gérant** (routeurs + vouchers) ou **Employé** (vente vouchers)
- Gestion : `/accounts/team/`

## Templates login MikroTik

- 3 templates système + création personnalisée
- Variables : `{{wifi_name}}`, `{{company_name}}`, `{{primary_color}}`, `{{background_color}}`
- Aperçu web + téléchargement `login.html` pour le routeur
- Assignation par routeur dans les paramètres du MikroTik


Projet développé pour Niger Certify — usage commercial selon votre déploiement.
