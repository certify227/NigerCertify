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

## Abonnements & paiement

L'activation des forfaits est simulée. Pour la production, intégrer :

- Stripe / PayPal pour cartes
- Mobile Money (Orange, MTN, etc.) pour le Niger et l'Afrique de l'Ouest

## Structure

```
wifizone/backend/
  accounts/    — utilisateurs opérateurs
  billing/     — forfaits et abonnements
  routers/     — routeurs MikroTik + service API
  hotspots/    — profils, vouchers, rapports
  dashboard/   — landing + tableau de bord
```

## Licence

Projet développé pour Niger Certify — usage commercial selon votre déploiement.
