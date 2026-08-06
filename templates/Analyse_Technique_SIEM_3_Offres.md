# Analyse technique comparative — Acquisition SIEM

**Document** : Analyse technique des offres SIEM  
**Date** : 6 août 2026  
**Version** : 1.0  
**Classification** : Interne  

---

## Table des matières

1. [Objet et périmètre](#1-objet-et-périmètre)
2. [Méthodologie d'évaluation](#2-méthodologie-dévaluation)
3. [Synthèse exécutive](#3-synthèse-exécutive)
4. [Offre A — Microsoft Sentinel](#4-offre-a--microsoft-sentinel)
5. [Offre B — FortiSIEM](#5-offre-b--fortisiem)
6. [Offre C — Wazuh](#6-offre-c--wazuh)
7. [Matrice comparative](#7-matrice-comparative)
8. [Analyse des écarts et risques](#8-analyse-des-écarts-et-risques)
9. [Adéquation budget et dimensionnement](#9-adéquation-budget-et-dimensionnement)
10. [Recommandation technique](#10-recommandation-technique)
11. [Prochaines étapes](#11-prochaines-étapes)

---

## 1. Objet et périmètre

### 1.1 Objectif

Ce document présente l'analyse technique comparative de **trois offres SIEM** en vue d'une acquisition, sans traitement du NAC (document distinct prévu).

### 1.2 Offres analysées

| Réf. | Produit SIEM | Éditeur | Modèle de déploiement |
|------|--------------|---------|------------------------|
| **A** | Microsoft Sentinel | Microsoft | SaaS Azure / hybride |
| **B** | FortiSIEM | Fortinet | On-prem / hybride |
| **C** | Wazuh | Wazuh Inc. (OSS) | On-prem / cloud managé |

### 1.3 Contraintes et priorités projet

| Paramètre | Valeur |
|-----------|--------|
| Budget TCO cible (3 ans) | **50 000 000 FCFA** (~76 220 € HT, taux 1 € = 655,957 FCFA) |
| Offre prioritaire | **Offre A — Microsoft Sentinel** |
| SOC | Interne |
| Écosystème cible | Microsoft (M365, Entra ID) |
| Exigence souveraineté | Région Azure EU acceptable |
| Périmètre indicatif | ~450 utilisateurs, ~100 EPS, ~25 Go/jour, 2 sites |

### 1.4 Hors périmètre

- NAC (Network Access Control) — analyse séparée
- Offres commerciales finales et SLA contractuels
- Audit de sécurité sur l'infrastructure existante

---

## 2. Méthodologie d'évaluation

### 2.1 Axes d'analyse

L'évaluation porte sur sept familles de critères techniques :

1. **Fonctionnalités et détection** — collecte, corrélation, UEBA, threat intelligence, SOAR
2. **Architecture et performance** — scalabilité, HA, rétention, latence, modèle de déploiement
3. **Intégrations et écosystème** — IAM, EDR, réseau, cloud, ticketing
4. **Exploitation et usabilité SOC** — ergonomie, tuning, RBAC, charge administrative
5. **Sécurité, conformité et gouvernance** — chiffrement, souveraineté, audit, réglementation
6. **Support, formation et roadmap** — SLA, transfert de compétences, pérennité
7. **TCO et rapport qualité-prix** — clarté licence, coûts cachés, adéquation budget

### 2.2 Échelle de notation

| Note | Signification |
|------|---------------|
| 5 | Excellent — dépasse le besoin |
| 4 | Bon — conforme au besoin |
| 3 | Acceptable — écarts mineurs |
| 2 | Insuffisant — écarts majeurs |
| 1 | Très insuffisant |
| 0 | Absent / non conforme |

### 2.3 Pondérations appliquées (priorité Sentinel)

| Famille | Poids |
|---------|-------|
| Fonctionnalités & détection | 30 % |
| Intégrations & écosystème | 25 % |
| Architecture & performance | 15 % |
| Exploitation & usabilité SOC | 10 % |
| Sécurité, conformité, gouvernance | 10 % |
| Support, formation, roadmap | 5 % |
| TCO / rapport qualité-prix | 5 % |

---

## 3. Synthèse exécutive

### 3.1 Résultats clés

| Indicateur | Offre A | Offre B | Offre C |
|------------|---------|---------|---------|
| Score SIEM pondéré (/5) | **4,44** | 3,83 | 3,38 |
| TCO 3 ans estimé (FCFA) | **46,5 M** ✅ | 182 M ❌ | 53,5 M ⚠️ |
| Adéquation budget 50 M FCFA | **Oui** | Non | Limite |
| Intégration M365 / Entra | **Excellente** | Partielle | Partielle |
| SOAR natif | **Complet** | Limité | Basique |
| Souveraineté on-prem | Partielle | Bonne | **Excellente** |

### 3.2 Lecture rapide

- **Offre A (Sentinel)** : meilleure adéquation technique et budgétaire pour un contexte Microsoft, avec le niveau de détection et d'automatisation le plus élevé dans l'enveloppe 50 M FCFA.
- **Offre B (FortiSIEM)** : SIEM robuste, particulièrement aligné avec un parc Fortinet, mais TCO incompatible avec le budget actuel.
- **Offre C (Wazuh)** : alternative open source souveraine, TCO licence minimal, mais charge opérationnelle et écarts fonctionnels (UEBA, SOAR, M365) plus importants.

---

## 4. Offre A — Microsoft Sentinel

### 4.1 Description produit

Microsoft Sentinel est un SIEM/SOAR cloud natif, intégré à l'écosystème Microsoft Security (Defender, Entra ID, Purview). Il s'appuie sur Azure Log Analytics pour l'ingestion et le stockage des journaux, avec des capacités d'analyse via **KQL** (Kusto Query Language).

### 4.2 Architecture technique

| Composant | Description |
|-----------|-------------|
| Ingestion | Connecteurs natifs, API, syslog/CEF via AMA |
| Stockage | Log Analytics workspace (hot) + Archive / ADX (cold) |
| Analyse | KQL, règles analytics, NRT rules |
| Automatisation | Playbooks Sentinel, Azure Logic Apps |
| Agents | Azure Monitor Agent (AMA) — remplace Log Analytics Agent |
| HA / PRA | SLA Azure, redondance régionale |

**Modèle** : SaaS Azure avec extension hybride (agents on-prem). Pas d'infrastructure SIEM à maintenir localement.

### 4.3 Fonctionnalités de détection

| Capacité | Évaluation | Commentaire |
|----------|------------|-------------|
| Collecte multi-sources | ⭐⭐⭐⭐⭐ | Connecteurs cloud natifs, AMA, API, syslog |
| Corrélation temps réel | ⭐⭐⭐⭐⭐ | Analytics rules, scheduled queries, NRT |
| UEBA | ⭐⭐⭐⭐ | Add-on Sentinel UEBA / corrélation Defender XDR |
| Threat Intelligence | ⭐⭐⭐⭐⭐ | Microsoft TI, STIX/TAXII, enrichissement Defender |
| SOAR / playbooks | ⭐⭐⭐⭐⭐ | Playbooks natifs + Logic Apps |
| Cas d'usage pré-packagés | ⭐⭐⭐⭐⭐ | Solution gallery, templates MITRE, cloud, identity |
| Hunting / forensics | ⭐⭐⭐⭐⭐ | KQL, notebooks, Defender advanced hunting |
| Reporting / conformité | ⭐⭐⭐⭐ | Workbooks, Power BI, rapports Azure |

### 4.4 Intégrations

| Source | Niveau | Détail |
|--------|--------|--------|
| Entra ID / Azure AD | **Natif** | Sign-in logs, audit, Identity Protection |
| Microsoft 365 | **Natif** | Exchange, SharePoint, Teams, Defender for Office |
| Defender XDR / EDR | **Natif** | Alertes, incidents, advanced hunting |
| Azure (IaaS/PaaS) | **Natif** | Activity Log, NSG, Key Vault, etc. |
| AWS / GCP | Bon | Connecteurs disponibles |
| Firewall / proxy | Bon | Palo Alto, Fortinet, Check Point, etc. |
| Ticketing | Bon | ServiceNow, Jira via Logic Apps |
| Active Directory on-prem | Bon | Via AMA + connecteurs |

### 4.5 Exploitation SOC

**Points positifs** :
- Console unifiée Microsoft Security (si Defender deployé)
- RBAC Azure granulaire, multi-workspace
- Documentation et contenu Microsoft très fournis (GitHub, Learn)
- Scalabilité sans dimensionnement infra locale

**Points d'attention** :
- **Courbe d'apprentissage KQL** — compétence clé pour analysts
- Tuning des règles nécessaire pour limiter faux positifs
- **Gestion des coûts d'ingestion** — surveillance continue requise
- Dépendance à la connectivité Azure

### 4.6 Sécurité et conformité

- Chiffrement en transit (TLS) et au repos (Azure Storage)
- Hébergement régional (France, EU) — souveraineté partielle
- Certifications : ISO 27001, SOC 1/2/3, RGPD, HIPAA (Azure)
- Audit trail Azure Activity Log

### 4.7 Modèle économique

| Élément | Description |
|---------|-------------|
| Licence | Ingestion (GB/jour) + rétention + fonctionnalités |
| Coûts variables | Ingestion burst, archive longue durée, connecteurs premium |
| Coûts fixes | Intégration, formation KQL, accompagnement |
| Optimisation | Filtrage AMA, tables de transformation, commitment Azure |

**TCO estimé 3 ans** : **~46,5 M FCFA** (périmètre calibré budget)

### 4.8 Synthèse Offre A

| Forces | Faiblesses |
|--------|------------|
| Meilleure intégration Microsoft | Dépendance cloud Azure |
| SOAR et détection avancés | Modèle licence ingestion complexe |
| Scalabilité sans infra locale | Courbe KQL |
| Dans le budget 50 M FCFA | Coûts ingestion à monitorer |
| Roadmap et pérennité Microsoft | Souveraineté = cloud régional |

---

## 5. Offre B — FortiSIEM

### 5.1 Description produit

FortiSIEM est le SIEM de Fortinet, orienté corrélation temps réel et supervision de la sécurité dans un écosystème Fortinet (FortiGate, FortiEDR, FortiAnalyzer). Déploiement typique on-prem ou hybride avec collectors et appliances.

### 5.2 Architecture technique

| Composant | Description |
|-----------|-------------|
| Ingestion | Agents FortiSIEM, syslog, SNMP, API, WMI |
| Stockage | Appliances FortiSIEM / collectors, rétention locale |
| Analyse | Corrélation multi-étapes temps réel, FortiView |
| Automatisation | Actions intégrées ; FortiSOAR en complément |
| HA | Cluster collectors + appliances redondées |

**Modèle** : On-prem / hybride — infrastructure à dimensionner et maintenir.

### 5.3 Fonctionnalités de détection

| Capacité | Évaluation | Commentaire |
|----------|------------|-------------|
| Collecte multi-sources | ⭐⭐⭐⭐ | Agents, syslog, API — large couverture |
| Corrélation temps réel | ⭐⭐⭐⭐ | Multi-étapes, règles custom |
| UEBA | ⭐⭐⭐ | Analyse comportementale limitée vs leaders |
| Threat Intelligence | ⭐⭐⭐⭐ | FortiGuard TI intégré |
| SOAR / playbooks | ⭐⭐⭐ | Automatisation basique ; FortiSOAR séparé |
| Cas d'usage pré-packagés | ⭐⭐⭐⭐ | Templates secteur / compliance |
| Hunting / forensics | ⭐⭐⭐ | FortiView — moins riche que KQL |
| Reporting / conformité | ⭐⭐⭐⭐ | Dashboards opérationnels |

### 5.4 Intégrations

| Source | Niveau | Détail |
|--------|--------|--------|
| FortiGate / Fortinet | **Excellent** | Intégration native, corrélation directe |
| FortiEDR / FortiClient | **Excellent** | Stack unifiée |
| Active Directory | Bon | WMI, LDAP |
| Entra ID / M365 | Partiel | Connecteurs moins exhaustifs que Sentinel |
| AWS / Azure / GCP | Partiel | Connecteurs cloud présents mais limités |
| Ticketing | Partiel | Connecteurs disponibles |
| Multi-vendeurs réseau | Bon | Cisco, Palo Alto via syslog/API |

### 5.5 Exploitation SOC

**Points positifs** :
- Console familière pour équipes Fortinet / réseau
- Administration centralisée si stack Fortinet existante
- Bonne documentation Fortinet et parcours NSE (formation)

**Points d'attention** :
- UEBA et SOAR avancés nécessitent produits complémentaires
- Licences multiples (SIEM + FortiCare + appliances)
- Dimensionnement appliances pour montée en charge

### 5.6 Sécurité et conformité

- Chiffrement configurable (transit / repos)
- Données on-prem — souveraineté maximale
- Reporting conformité intégré (PCI, HIPAA, etc.)
- Support FortiCare 24/7 (selon contrat)

### 5.7 Modèle économique

| Élément | Description |
|---------|-------------|
| Licence | Par EPS, devices, ou appliances |
| Coûts fixes | Appliances, collectors, FortiCare renew |
| Coûts variables | Modules optionnels, montée en charge |

**TCO estimé 3 ans** : **~182 M FCFA** — **hors budget 50 M FCFA**

### 5.8 Synthèse Offre B

| Forces | Faiblesses |
|--------|------------|
| Intégration Fortinet native excellente | **TCO ~3,6× budget** |
| On-prem, souveraineté locale | UEBA limité |
| Bonne corrélation temps réel | SOAR = FortiSOAR séparé |
| Références mid-market | Cloud / M365 moins riches |
| | Vendor lock-in Fortinet |

---

## 6. Offre C — Wazuh

### 6.1 Description produit

Wazuh est une plateforme open source de sécurité unifiée (SIEM, XDR, compliance) basée sur des agents légers, un manager central et un indexer OpenSearch pour stockage et recherche.

### 6.2 Architecture technique

| Composant | Description |
|-----------|-------------|
| Agents | Wazuh agent (FIM, vuln, logs, compliance) |
| Manager | Règles, corrélation, API REST |
| Indexer | OpenSearch / Wazuh indexer (stockage, recherche) |
| Dashboard | Wazuh Dashboard (OpenSearch Dashboards) |
| HA | Cluster manager + indexer (à architecturer) |

**Modèle** : On-prem par défaut ; Wazuh Cloud en option managé.

### 6.3 Fonctionnalités de détection

| Capacité | Évaluation | Commentaire |
|----------|------------|-------------|
| Collecte multi-sources | ⭐⭐⭐⭐ | Agents, syslog, modules cloud |
| Corrélation temps réel | ⭐⭐⭐⭐ | Règles YAML, decoders |
| UEBA | ⭐⭐ | Pas d'UEBA natif |
| Threat Intelligence | ⭐⭐⭐ | Intégrations MISP, VirusTotal possibles |
| SOAR / playbooks | ⭐⭐ | Active Response basique |
| Cas d'usage pré-packagés | ⭐⭐⭐⭐ | PCI, CIS, GDPR, HIPAA templates |
| Hunting / forensics | ⭐⭐⭐⭐ | Indexer + dashboards + API |
| Reporting / conformité | ⭐⭐⭐ | Dashboards OSS, personnalisation requise |

### 6.4 Intégrations

| Source | Niveau | Détail |
|--------|--------|--------|
| Souveraineté / on-prem | **Excellent** | 100 % local possible |
| AWS / Azure / GCP | Bon | Modules cloud intégrés |
| Office 365 | Partiel | Module O365 disponible |
| Entra ID / AD | Partiel | Via agents / API |
| EDR commercial | Partiel | Pas d'intégration native tierce |
| Firewall | Bon | Syslog standard |
| Ticketing | Partiel | Webhooks, scripts custom |

### 6.5 Exploitation SOC

**Points positifs** :
- Pas de licence logicielle (open source)
- Contrôle total architecture et données
- Communauté active, documentation fournie
- Modules compliance prêts à l'emploi

**Points d'attention** :
- **Charge opérationnelle élevée** : patches, cluster, tuning, scaling
- Interface moins polie que solutions commerciales
- Compétences Linux / OpenSearch / YAML requises
- Support commercial en option (Wazuh Inc.)

### 6.6 Sécurité et conformité

- Chiffrement TLS configurable
- Données 100 % on-prem — souveraineté maximale
- Modules compliance : PCI-DSS, HIPAA, CIS, GDPR
- Audit des actions administrateurs

### 6.7 Modèle économique

| Élément | Description |
|---------|-------------|
| Licence | Open source (gratuit) |
| Coûts réels | Infrastructure, intégration, RH, support optionnel |
| Coûts cachés | Montée en charge cluster, expertise interne |

**TCO estimé 3 ans** : **~53,5 M FCFA** — légèrement au-dessus du budget

### 6.8 Synthèse Offre C

| Forces | Faiblesses |
|--------|------------|
| Souveraineté totale | UEBA / SOAR faibles |
| TCO licence minimal | Charge ops élevée |
| Flexibilité architecture | M365 / Entra moins natifs |
| Templates compliance | Moins références enterprise |
| | Compétences OSS requises |

---

## 7. Matrice comparative

### 7.1 Fonctionnalités

| Critère | A — Sentinel | B — FortiSIEM | C — Wazuh |
|---------|:------------:|:-------------:|:---------:|
| Collecte multi-sources | 5 | 4 | 4 |
| Corrélation temps réel | 5 | 4 | 4 |
| UEBA / ML | 4 | 3 | 2 |
| Threat Intelligence | 5 | 4 | 3 |
| SOAR / automatisation | 5 | 3 | 2 |
| Cas d'usage pré-packagés | 5 | 4 | 4 |
| Hunting / forensics | 5 | 3 | 4 |
| Reporting / conformité | 4 | 4 | 3 |

### 7.2 Architecture

| Critère | A | B | C |
|---------|:-:|:-:|:-:|
| Scalabilité | 5 | 4 | 3 |
| Haute disponibilité | 5 | 4 | 3 |
| Rétention / archive | 4 | 4 | 3 |
| Latence alerting | 4 | 4 | 3 |
| Modèle déploiement | SaaS/hybride | On-prem/hybride | On-prem |

### 7.3 Intégrations

| Critère | A | B | C |
|---------|:-:|:-:|:-:|
| Entra ID / M365 | 5 | 3 | 3 |
| EDR / XDR | 5 | 5* | 3 |
| Firewall / réseau | 4 | 5* | 4 |
| Cloud (AWS/Azure/GCP) | 5 | 3 | 4 |
| Ticketing | 4 | 3 | 3 |

*\* FortiEDR / FortiGate si stack Fortinet*

### 7.4 Exploitation et TCO

| Critère | A | B | C |
|---------|:-:|:-:|:-:|
| Ergonomie SOC | 3 | 4 | 3 |
| Charge administration | 3 | 4 | 2 |
| Clarté licence | 2 | 3 | 5 |
| Adéquation budget 50 M FCFA | 5 | 2 | 4 |
| Coûts cachés | 3 | 3 | 3 |

### 7.5 Scores pondérés

| Offre | Score SIEM (/5) | Rang |
|-------|-----------------|------|
| **A — Sentinel** | **4,44** | **1** |
| B — FortiSIEM | 3,83 | 2 |
| C — Wazuh | 3,38 | 3 |

---

## 8. Analyse des écarts et risques

### 8.1 Écarts fonctionnels majeurs

| Écart | Impact | Offres concernées |
|-------|--------|-------------------|
| Absence UEBA natif | Détection comportementale limitée | C |
| SOAR incomplet | Automatisation incident manuelle | B, C |
| Intégration M365 partielle | Corrélation identity/cloud réduite | B, C |
| TCO hors budget | Non sélectionnable sans arbitrage | B |
| Charge ops OSS | Besoin compétences internes | C |

### 8.2 Registre des risques

| ID | Risque | Prob. | Impact | Offre | Mitigation |
|----|--------|-------|--------|-------|------------|
| R1 | Explosion coûts ingestion | Moyenne | Élevé | A | Filtrage AMA, commitment Azure, monitoring |
| R2 | Dépendance Azure | Faible | Moyen | A | Région EU, PRA Azure documenté |
| R3 | Courbe KQL | Élevée | Moyen | A | Formation SOC 5 jours, templates |
| R4 | TCO FortiSIEM | Élevée | Élevé | B | Hors sélection budget actuel |
| R5 | Charge cluster Wazuh | Moyenne | Élevé | C | Dimensionnement, support commercial |
| R6 | Faux positifs | Moyenne | Moyen | Tous | Tuning règles, phase pilote |

### 8.3 Dépendances techniques

| Dépendance | A | B | C |
|------------|:-:|:-:|:-:|
| Connectivité Internet / Azure | Requise | Optionnelle | Optionnelle |
| Active Directory / Entra ID | Forte | Forte | Moyenne |
| Agents endpoint | AMA | FortiSIEM agent | Wazuh agent |
| Infrastructure locale | Minimale | Appliances | Cluster OpenSearch |

---

## 9. Adéquation budget et dimensionnement

### 9.1 Budget de référence

| Paramètre | Valeur |
|-----------|--------|
| Budget max TCO 3 ans | 50 000 000 FCFA |
| Référence EUR | ~76 220 € HT |

### 9.2 TCO comparatif (estimations indicatives)

| Poste | Offre A (FCFA) | Offre B (FCFA) | Offre C (FCFA) |
|-------|----------------|----------------|----------------|
| Licences SIEM 3 ans | ~34,5 M | ~87 M | ~0 |
| Intégration / règles | ~6,5 M | ~19 M | ~9,5 M |
| Formation | ~3 M | ~4,5 M | ~2 M |
| Infrastructure | Inclus Azure | ~25 M | ~5,5 M |
| Divers | ~1 M | ~5 M | ~1,5 M |
| **Total 3 ans** | **~46,5 M** ✅ | **~182 M** ❌ | **~53,5 M** ⚠️ |

### 9.3 Périmètre calibré pour Offre A (50 M FCFA)

| Paramètre | Valeur |
|-----------|--------|
| Utilisateurs | ~450 |
| EPS | ~100 |
| Volume logs | ~25 Go/jour (filtré) |
| Sites | 2 |
| Rétention chaude | 60 jours |
| Rétention archive | 12 mois (basique) |

**Note** : une augmentation du périmètre (EPS, rétention, sites) nécessite une révision budgétaire ou un phasage.

---

## 10. Recommandation technique

### 10.1 Décision

**Recommandation : Offre A — Microsoft Sentinel** (prioritaire)

### 10.2 Justification

1. **Adéquation budget** : seul SIEM commercial aligné avec 50 M FCFA sur 3 ans (~46,5 M FCFA estimés).
2. **Intégration Microsoft** : native Entra ID, M365, Defender — avantage décisif dans un contexte Microsoft.
3. **Capacités SIEM/SOAR** : meilleur niveau de détection, hunting KQL et automatisation (playbooks, Logic Apps).
4. **Scalabilité** : pas d'infrastructure SIEM locale à dimensionner ; montée en charge via Azure.
5. **Score pondéré** : 4,44/5 — premier rang sur les critères techniques pondérés.

### 10.3 Conditions et réserves

| Condition | Description |
|-----------|-------------|
| Région Azure | Confirmer hébergement EU (France / Europe) |
| Ingestion | Mettre en place filtrage AMA avant production |
| Formation | Planifier montée en compétence KQL (5 jours minimum) |
| Engagement | Négocier commitment Azure / EES Microsoft |
| Phasage | Déploiement progressif par sources prioritaires |

### 10.4 Scénarios alternatifs

| Scénario | Condition | Offre |
|----------|-----------|-------|
| Plan B souveraineté | Refus cloud absolu | C — Wazuh |
| Plan B stack Fortinet | Parc Fortinet dominant + budget augmenté | B — FortiSIEM |
| Plan B hybride | Sentinel + Wazuh pour sources on-prem critiques | A + C |

---

## 11. Prochaines étapes

| # | Action | Responsable | Délai indicatif |
|---|--------|-------------|-----------------|
| 1 | PoC Sentinel 30 jours (M365, Entra, firewall) | RSSI / DSI | M+1 |
| 2 | Atelier filtrage ingestion / dimensionnement AMA | Intégrateur | M+1 |
| 3 | Négociation commitment Azure / EES Microsoft | Achats | M+2 |
| 4 | Formation KQL SOC (5 jours) | RSSI | M+2 |
| 5 | Validation région Azure et conformité données | DSI / Juridique | M+1 |
| 6 | Déploiement progressif sources prioritaires | DSI | M+3 à M+6 |
| 7 | Tuning règles et réduction faux positifs | SOC | M+4 à M+8 |

---

## Annexe A — Sources et références

| Ressource | URL |
|-----------|-----|
| Microsoft Sentinel | https://learn.microsoft.com/azure/sentinel/ |
| FortiSIEM | https://docs.fortinet.com/product/fortisiem |
| Wazuh | https://documentation.wazuh.com/ |
| Grille Excel associée | `Evaluation_SIEM_NAC_3_offres_REMPLI.xlsx` |

---

## Annexe B — Historique du document

| Version | Date | Auteur | Modifications |
|---------|------|--------|---------------|
| 1.0 | 06/08/2026 | Évaluation agent | Version initiale — analyse SIEM |

---

*Document généré dans le cadre de l'évaluation comparative SIEM. Les estimations TCO sont indicatives et doivent être validées par les offres commerciales des intégrateurs.*
