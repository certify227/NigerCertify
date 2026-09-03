# Décisions produit — ZumunciTravel (choix expert)

Document de cadrage pris faute de réponses détaillées.  
Objectif : un **pilote réaliste, sûr et lançable** au Niger.

## Synthèse des choix

| Sujet | Décision |
|---|---|
| Modes au lancement | **Covoiturage + taxi brousse** prioritaires ; bus disponible mais secondaire |
| Couverture | **Les 8 régions du Niger** : Agadez, Diffa, Dosso, Maradi, Tahoua, Tillabéri, Zinder, Niamey |
| KYC | Validation **interne admin**, délai cible **≤ 24 h** |
| Contact | Masqué jusqu’au paiement ; puis **téléphone + bouton WhatsApp** |
| Chat in-app | **Non** en V1 (trop lourd) |
| Cash | **Interdit en covoiturage** ; toléré bus/taxi brousse avec avertissement |
| Monétisation | **Commission 10 %** prélevée sur le prix payé |
| Langue V1 | **Français** (haoussa en phase 2) |
| Client | **PWA** d’abord (Android natif plus tard) |
| Relations déplacées | Charte stricte + option trajet **priorité femmes** + signalement |
| Horaires | Avertissement fort pour départs **avant 05:00 ou après 20:00** |
| Annulation V1 | Annulation simple avant le jour du départ (sans pénalité auto) |

## Pourquoi ces choix

1. **8 régions** : couverture nationale dès le départ (chefs-lieux + villes secondaires).  
2. **Pas de cash en covoiturage** : principal vecteur d’arnaque hors plateforme.  
3. **WhatsApp après paiement** : usage réel au Niger, sans exposer le numéro trop tôt.  
4. **10 %** : simple à expliquer, finance KYC/support sans tuer l’offre.  
5. **PWA** : déploiement rapide, Android-first via navigateur.  
6. **Priorité femmes** : levier concret contre l’insécurité / comportements déplacés.

## Hors scope pilote

- USSD / SMS recherche  
- Assurance voyage  
- Multi-pays UEMOA  
- Espace compagnies bus avancé  
- Messagerie temps réel in-app  

## KPI pilote (8 semaines)

- ≥ 100 comptes vérifiés  
- ≥ 40 trajets publiés / semaine sur axes pilotes  
- ≥ 60 % paiements Mobile Money réussis  
- < 5 % signalements graves / réservations  
