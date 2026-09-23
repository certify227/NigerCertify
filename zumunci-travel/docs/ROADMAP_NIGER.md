# Feuille de route — déploiement au Niger

## Phase 0 — Fondation (fait dans ce dépôt)

- [x] Vision produit adaptée au Niger
- [x] API FastAPI (auth téléphone, trajets, réservations, Mobile Money mock)
- [x] PWA React mobile-first
- [x] Seed villes nigériennes + comptes démo
- [x] Docker Compose

## Phase 1 — Pilote Niamey (4–8 semaines produit)

**Objectif :** 200–500 utilisateurs actifs, axes Niamey ↔ Dosso / Maradi / Tillabéri.

1. Brancher **Orange Money** (sandbox puis prod) — mock + flux confirm en place
2. Vérification téléphone OTP SMS (ex. Twilio, ou API opérateur) — OTP simulé en place
3. Support WhatsApp deep-link vers le conducteur — fait
4. Modération manuelle des trajets (admin basique) — fait (`/admin/rides`)
5. Landing marketing en français + haoussa (messages clés) — fait (toggle FR/HA)

**KPI pilote :** trajets publiés / semaine, taux de réservation, % paiements réussis, NPS.

## Phase 2 — Confiance & densité

1. KYC pièce d’identité (photo) — fait (upload data-URL + revue admin)
2. Système d’avis bi-directionnel — fait
3. Signalement / blacklist — fait (auto-suspension après N signalements sérieux)
4. Profil public conducteur — fait (`/users/{id}/public`, UI `/drivers/:id`)
5. Notifications SMS simulées + inbox — fait (confirm paiement + création réservation)
6. Assurance trajet optionnelle — fait (`with_insurance`, partenaire mock)
7. Onboarding compagnies de bus — fait (Rimbo / Sahel / Azawad, UI `/companies`)

## Phase 3 — Couverture nationale

1. Ouverture Zinder, Maradi, Agadez, Tahoua — fait (8 régions)
2. Agents terrain (ambassadeurs gares routières) — fait (`/agents`)
3. SMS de confirmation (bas débit) — fait (simulé)
4. USSD `*789#` pour recherche simple — fait (simulateur `/ussd`)

## Phase 4 — Scale UEMOA

1. Burkina, Mali, Sénégal (même devise XOF)
2. Multi-langue FR / HA / Zarma — partiel (hero FR/HA/ZAR)
3. Data warehouse + fraude

## Organisation recommandée (équipe minimale)

| Rôle | Focus |
|---|---|
| 1 Product / Ops | Gares, transporteurs, support |
| 1 Backend | API, paiements, SMS |
| 1 Frontend | PWA, perf 3G |
| 1 Growth | WhatsApp, radio, ambassadeurs |

## Budget technique indicatif (MVP hébergé)

- VPS 2 vCPU / 4 Go : ~10–20 €/mois
- Domaine `.ne` ou `.com` + SSL
- SMS OTP : selon volume
- Frais Mobile Money : selon agrégateur (PayGate, Hub2, CinetPay, etc.)

## Conformité & risques

- Déclarer l’activité selon le cadre nigérien (commerce électronique / transport)
- CGU claires : ZumunciTravel = mise en relation, pas transporteur
- Données personnelles : minimisation, consentement, stockage sécurisé
- Sécurité des trajets : numéro d’urgence, partage d’itinéraire (phase 2)
