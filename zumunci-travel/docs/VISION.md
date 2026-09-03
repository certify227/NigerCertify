# ZumunciTravel — Vision produit (Niger)

> **ZumunciTravel** signifie *voyage / trajet* en haoussa.  
> Plateforme de mise en relation pour le transport interurbain au Niger.

## Problème

Au Niger, le transport interurbain repose surtout sur :

- taxis brousse et véhicules informels ;
- compagnies de bus locales ;
- partage de places « de bouche à oreille » ;
- paiements cash / Mobile Money ;
- faible couverture carte bancaire et connexion instable.

Il n’existe pas d’équivalent local mature à BlaBlaCar adapté à ces contraintes.

## Principes de confiance

- Vérification d'identité **avant** publication ou réservation
- Contact masqué jusqu'au paiement
- Plateforme de **transport uniquement** (anti relations déplacées)
- Signalement arnaque / harcèlement

## Solution

Marketplace **mobile-first** qui connecte :

1. **Conducteurs / transporteurs** qui ont des places libres  
2. **Voyageurs** qui cherchent un trajet à petit prix  
3. **Compagnies de bus** (phase 2) qui publient des départs

## Différences clés vs BlaBlaCar Europe

| Europe (BlaBlaCar) | Niger (ZumunciTravel) |
|---|---|
| Cartes bancaires | Orange Money, Airtel Money, Moov Money, cash |
| Smartphones haut de gamme | Android entrée/milieu de gamme, 3G |
| Identité forte (KYC) | Téléphone + pièce d’identité progressive |
| Train / bus nationaux digitaux | Bus + taxi brousse + covoiturage |
| Latence faible | Offline-friendly, SMS/USSD en phase 2 |
| Prix en euros | Franc CFA (XOF) |

## Personas

- **Aïcha** (voyageuse, Niamey → Maradi) : veut un prix clair, un contact WhatsApp/téléphone, et payer en Orange Money.
- **Ibrahim** (conducteur) : part régulièrement, veut remplir ses places et recevoir le paiement sans litige.
- **Compagnie Sahel Bus** (phase 2) : publie des départs hebdomadaires.

## Périmètre MVP (phase 1)

- Inscription / connexion (téléphone + mot de passe)
- Publier un trajet (ville, date, places, prix XOF)
- Rechercher des trajets
- Réserver une place
- Paiement Mobile Money **simulé** (webhook-ready)
- Profils + notation simple
- Villes du Niger préchargées

## Hors scope MVP

- App native iOS/Android (PWA d’abord)
- USSD
- Agrégation train
- Assurance voyage
- KYC vidéo

## Roadmap

1. **MVP** — covoiturage + réservation + Mobile Money mock  
2. **Confiance** — vérif pièce, avis, signalement, chat  
3. **Supply bus** — compagnies partenaires  
4. **Canaux bas débit** — SMS confirmation, USSD recherche  
5. **Scale** — multi-pays UEMOA (BF, ML, SN…)
