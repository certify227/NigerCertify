# Feuille de route — déploiement au Niger

## Phase 0 — Fondation (fait dans ce dépôt)

- [x] Vision produit adaptée au Niger
- [x] API FastAPI (auth téléphone, trajets, réservations, Mobile Money mock)
- [x] PWA React mobile-first
- [x] Seed villes nigériennes + comptes démo
- [x] Docker Compose

## Phase 1 — Pilote Niamey (4–8 semaines produit)

**Objectif :** 200–500 utilisateurs actifs, axes Niamey ↔ Dosso / Maradi / Tillabéri.

1. Brancher **Orange Money** (sandbox puis prod)
2. Vérification téléphone OTP SMS (ex. Twilio, ou API opérateur)
3. Support WhatsApp deep-link vers le conducteur
4. Modération manuelle des trajets (admin basique)
5. Landing marketing en français + haoussa (messages clés)

**KPI pilote :** trajets publiés / semaine, taux de réservation, % paiements réussis, NPS.

## Phase 2 — Confiance & densité

1. KYC pièce d’identité (photo)
2. Système d’avis bi-directionnel
3. Signalement / blacklist
4. Assurance partenariat (optionnel)
5. Onboarding compagnies de bus (Sahel, Rimbo, etc.)

## Phase 3 — Couverture nationale

1. Ouverture Zinder, Maradi, Agadez, Tahoua
2. Agents terrain (ambassadeurs gares routières)
3. SMS de confirmation (bas débit)
4. USSD `*XYZ#` pour recherche simple (inclusion)

## Phase 4 — Scale UEMOA

1. Burkina, Mali, Sénégal (même devise XOF)
2. Multi-langue FR / HA / Zarma
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
- CGU claires : Tafiya = mise en relation, pas transporteur
- Données personnelles : minimisation, consentement, stockage sécurisé
- Sécurité des trajets : numéro d’urgence, partage d’itinéraire (phase 2)
