#!/usr/bin/env python3
"""Remplit le template Excel avec l'évaluation Sentinel / FortiSIEM / Wazuh."""

from copy import copy
from pathlib import Path

from openpyxl import load_workbook

SRC = Path(__file__).resolve().parent / "Evaluation_SIEM_NAC_3_offres.xlsx"
OUT = Path(__file__).resolve().parent / "Evaluation_SIEM_NAC_3_offres_REMPLI.xlsx"

# (conformité, note, commentaire) pour A=Sentinel, B=FortiSIEM, C=Wazuh
SIEM_DATA = {
    5: (
        ("Oui", 5, "Connecteurs cloud natifs, AMA, API, syslog via CEF/AMA"),
        ("Oui", 4, "Collecte multi-vendeurs via agents FortiSIEM / collectors"),
        ("Oui", 4, "Agents Wazuh + syslog + modules cloud (AWS/Azure/GCP)"),
    ),
    6: (
        ("Oui", 5, "Règles analytics KQL, scheduled queries, NRT"),
        ("Oui", 4, "Règles temps réel + corrélation multi-étapes"),
        ("Oui", 4, "Règles custom YAML, decoders, corrélation intégrée"),
    ),
    7: (
        ("Partiel", 4, "UEBA via add-on Sentinel / intégration Defender XDR"),
        ("Partiel", 3, "Analyse comportementale limitée vs leaders UEBA"),
        ("Partiel", 2, "Pas d'UEBA natif ; détection par règles et FIM"),
    ),
    8: (
        ("Oui", 5, "Microsoft TI, STIX/TAXII, enrichissement Defender"),
        ("Oui", 4, "FortiGuard TI intégré"),
        ("Partiel", 3, "Intégration TI possible (MISP, VirusTotal, etc.)"),
    ),
    9: (
        ("Oui", 5, "Playbooks Sentinel + Logic Apps / Defender automation"),
        ("Partiel", 3, "Automatisation intégrée ; FortiSOAR en complément"),
        ("Partiel", 2, "Active Response basique ; pas de SOAR complet natif"),
    ),
    10: (
        ("Oui", 5, "Solution gallery, templates Microsoft (MITRE, cloud, identity)"),
        ("Oui", 4, "Use cases pré-packagés secteur / compliance"),
        ("Oui", 4, "Templates PCI-DSS, CIS, GDPR, NIST"),
    ),
    11: (
        ("Oui", 5, "Hunting KQL, notebooks, Defender advanced hunting"),
        ("Oui", 3, "FortiView / recherche ; moins riche que KQL"),
        ("Oui", 4, "Wazuh indexer + OpenSearch Dashboards / API"),
    ),
    12: (
        ("Oui", 4, "Workbooks, Power BI, rapports conformité Azure"),
        ("Oui", 4, "Dashboards opérationnels + reporting compliance"),
        ("Partiel", 3, "Dashboards OSS ; personnalisation technique requise"),
    ),
    14: (
        ("Oui", 5, "Scalabilité cloud Azure (ingestion massive)"),
        ("Oui", 4, "Scalable en cluster collectors / appliances"),
        ("Partiel", 3, "Scalable si architecture indexer/cluster dimensionnée"),
    ),
    15: (
        ("Oui", 5, "SLA Azure, redondance régionale"),
        ("Oui", 4, "HA collectors + appliances en mode cluster"),
        ("Partiel", 3, "HA possible (cluster) mais à architecturer"),
    ),
    16: (
        ("Oui", 4, "Rétention ADX / Archive ; coût long terme"),
        ("Oui", 4, "Rétention on-prem configurable par politique"),
        ("Partiel", 3, "Rétention liée au stockage OpenSearch / ILM"),
    ),
    17: (
        ("Oui", 4, "Alerting NRT ; latence dépend ingestion pipeline"),
        ("Oui", 4, "Corrélation temps réel performante"),
        ("Partiel", 3, "Bonne latence à l'échelle si cluster bien dimensionné"),
    ),
    18: (
        ("Oui", 5, "SaaS cloud Azure (hybride via AMA on-prem)"),
        ("Oui", 4, "On-prem / hybride / cloud collectors"),
        ("Oui", 5, "On-prem / cloud (Wazuh Cloud option) — open source"),
    ),
    20: (
        ("Oui", 5, "Intégration native Entra ID / Azure AD, Identity Protection"),
        ("Oui", 4, "Intégration AD / LDAP pour corrélation"),
        ("Partiel", 3, "Intégration AD via agents / API ; moins native"),
    ),
    21: (
        ("Oui", 5, "Defender XDR / EDR intégration native"),
        ("Oui", 5, "FortiEDR / FortiClient intégration forte"),
        ("Partiel", 3, "Agents Wazuh (FIM, vuln) ; pas EDR commercial complet"),
    ),
    22: (
        ("Oui", 4, "Connecteurs Palo Alto, Fortinet, Check Point, etc."),
        ("Oui", 5, "FortiGate intégration native excellente"),
        ("Oui", 4, "Syslog / intégrations firewall standards"),
    ),
    23: (
        ("Oui", 4, "Logic Apps, ServiceNow, Jira via connecteurs"),
        ("Partiel", 3, "Connecteurs ticketing disponibles mais limités"),
        ("Partiel", 3, "Intégrations webhook / scripts custom"),
    ),
    24: (
        ("Partiel", 3, "Via syslog générique ; pas couplage NAC natif"),
        ("Oui", 5, "Intégration FortiNAC native dans l'écosystème Fortinet"),
        ("Partiel", 2, "Réception événements NAC via syslog uniquement"),
    ),
    25: (
        ("Oui", 5, "M365, Azure natif ; connecteurs AWS/GCP"),
        ("Partiel", 3, "Connecteurs cloud présents mais moins exhaustifs"),
        ("Oui", 4, "Modules cloud AWS, Azure, GCP, Office 365"),
    ),
    27: (
        ("Partiel", 3, "Courbe KQL / Azure ; puissant mais exigeant"),
        ("Oui", 4, "Console unifiée Fortinet familière aux équipes réseau"),
        ("Partiel", 3, "Interface technique ; expertise OSS recommandée"),
    ),
    28: (
        ("Partiel", 3, "Tuning analytics rules nécessaire (faux positifs)"),
        ("Partiel", 3, "Tuning règles requis selon périmètre"),
        ("Partiel", 3, "Tuning règles / decoders indispensable"),
    ),
    29: (
        ("Oui", 5, "Azure RBAC, workspaces multi-équipes"),
        ("Oui", 4, "RBAC multi-organisation / multi-site"),
        ("Oui", 4, "RBAC Wazuh + multi-tenant possible"),
    ),
    30: (
        ("Partiel", 3, "Charge admin + gestion coûts ingestion"),
        ("Oui", 4, "Administration centralisée si stack Fortinet"),
        ("Partiel", 2, "Charge ops élevée (patch, cluster, règles)"),
    ),
    31: (
        ("Oui", 5, "Documentation Microsoft extensive + GitHub"),
        ("Oui", 4, "Documentation Fortinet + guides use cases"),
        ("Oui", 4, "Documentation Wazuh + communauté active"),
    ),
    33: (
        ("Oui", 5, "Chiffrement Azure (TLS, stockage chiffré)"),
        ("Oui", 4, "Chiffrement transit / repos selon déploiement"),
        ("Oui", 4, "TLS, chiffrement configurable OpenSearch"),
    ),
    34: (
        ("Partiel", 3, "Données dans région Azure choisie ; cloud US possible"),
        ("Oui", 4, "On-prem = souveraineté maximale"),
        ("Oui", 5, "100 % on-prem possible ; contrôle total des données"),
    ),
    35: (
        ("Oui", 5, "Azure Activity Log / audit intégré"),
        ("Oui", 4, "Journalisation admin appliances"),
        ("Oui", 4, "Audit des actions administrateurs"),
    ),
    36: (
        ("Oui", 5, "ISO 27001, SOC2, RGPD, certifications Azure"),
        ("Oui", 4, "Conformité sectorielle via reporting intégré"),
        ("Oui", 4, "Modules compliance PCI, HIPAA, CIS, GDPR"),
    ),
    38: (
        ("Oui", 4, "Support Microsoft entreprise (selon contrat)"),
        ("Oui", 4, "Support Fortinet 24/7 (selon contrat FortiCare)"),
        ("Partiel", 3, "Support communauté ; support commercial Wazuh en option"),
    ),
    39: (
        ("Oui", 4, "Formations Microsoft Learn / partenaires"),
        ("Oui", 4, "Formation Fortinet NSE disponible"),
        ("Partiel", 3, "Formation disponible ; montée en compétence interne"),
    ),
    40: (
        ("Oui", 5, "Roadmap Microsoft Security forte / pérennité"),
        ("Oui", 4, "Éditeur pérenne, roadmap intégration stack"),
        ("Oui", 4, "Projet OSS actif, adoption croissante"),
    ),
    41: (
        ("Oui", 5, "Références enterprise / secteur public mondial"),
        ("Oui", 4, "Références mid-market / entreprises stack Fortinet"),
        ("Partiel", 3, "Références croissantes ; moins enterprise historique"),
    ),
    43: (
        ("Partiel", 2, "Modèle ingestion GB/jour + coûts variables"),
        ("Partiel", 3, "Licence par EPS/devices — modèle compréhensible"),
        ("Oui", 5, "Open source + support optionnel — très clair"),
    ),
    44: (
        ("Partiel", 3, "Puissant mais coût élevé à l'échelle"),
        ("Oui", 4, "Bon rapport qualité-prix stack unifié"),
        ("Oui", 5, "Licence quasi nulle ; coût = infra + RH"),
    ),
    45: (
        ("Partiel", 2, "Coûts ingestion, archive, connecteurs, burst"),
        ("Partiel", 3, "Appliances, renew FortiCare, collectors"),
        ("Partiel", 3, "Coûts cachés : infra, expertise, montée en charge"),
    ),
}

# FortiNAC pour offre B uniquement ; A/C = SIEM seul
NAC_DATA = {
    5: (
        ("N/A", 0, "NAC non proposé dans l'offre A (SIEM seul)"),
        ("Oui", 5, "802.1X filaire et Wi-Fi natif FortiNAC"),
        ("N/A", 0, "NAC non proposé (Wazuh = SIEM/XDR open source)"),
    ),
    6: (
        ("N/A", 0, ""),
        ("Oui", 4, "MAB pour équipements non 802.1X"),
        ("N/A", 0, ""),
    ),
    7: (
        ("N/A", 0, ""),
        ("Oui", 5, "Portail captive + sponsoring invités"),
        ("N/A", 0, ""),
    ),
    8: (
        ("N/A", 0, ""),
        ("Oui", 5, "Politiques dynamiques VLAN / ACL / quarantine"),
        ("N/A", 0, ""),
    ),
    9: (
        ("N/A", 0, ""),
        ("Oui", 4, "Posture check (AV, patch) intégré"),
        ("N/A", 0, ""),
    ),
    10: (
        ("N/A", 0, ""),
        ("Oui", 4, "BYOD, employés, partenaires"),
        ("N/A", 0, ""),
    ),
    11: (
        ("N/A", 0, ""),
        ("Oui", 4, "Profilage IoT / OT / devices non managés"),
        ("N/A", 0, ""),
    ),
    13: (
        ("N/A", 0, ""),
        ("Oui", 4, "Découverte et inventaire réseau"),
        ("N/A", 0, ""),
    ),
    14: (
        ("N/A", 0, ""),
        ("Oui", 4, "Fingerprint actif / passif"),
        ("N/A", 0, ""),
    ),
    15: (
        ("N/A", 0, ""),
        ("Oui", 4, "Classification automatique des devices"),
        ("N/A", 0, ""),
    ),
    16: (
        ("N/A", 0, ""),
        ("Oui", 4, "Visibilité temps réel endpoint / switch / port"),
        ("N/A", 0, ""),
    ),
    18: (
        ("N/A", 0, ""),
        ("Oui", 4, "Multi-vendeurs switches (Cisco, Aruba, etc.)"),
        ("N/A", 0, ""),
    ),
    19: (
        ("N/A", 0, ""),
        ("Oui", 5, "Intégration FortiGate WLC / contrôleurs Wi-Fi"),
        ("N/A", 0, ""),
    ),
    20: (
        ("N/A", 0, ""),
        ("Oui", 4, "VPN / accès distant"),
        ("N/A", 0, ""),
    ),
    21: (
        ("N/A", 0, ""),
        ("Oui", 5, "AD / Entra ID / RADIUS / PKI"),
        ("N/A", 0, ""),
    ),
    22: (
        ("N/A", 0, ""),
        ("Partiel", 3, "Intégration MDM via API / posture"),
        ("N/A", 0, ""),
    ),
    23: (
        ("N/A", 0, ""),
        ("Oui", 5, "Intégration FortiSIEM + FortiGate"),
        ("N/A", 0, ""),
    ),
    25: (
        ("N/A", 0, ""),
        ("Oui", 5, "Mode audit puis enforce sans coupure"),
        ("N/A", 0, ""),
    ),
    26: (
        ("N/A", 0, ""),
        ("Oui", 4, "Déploiement agents / appliances standard Fortinet"),
        ("N/A", 0, ""),
    ),
    27: (
        ("N/A", 0, ""),
        ("Oui", 4, "HA policy server en cluster"),
        ("N/A", 0, ""),
    ),
    28: (
        ("N/A", 0, ""),
        ("Oui", 4, "Multi-sites / fédération"),
        ("N/A", 0, ""),
    ),
    30: (
        ("N/A", 0, ""),
        ("Partiel", 3, "Micro-segmentation via intégration FortiGate"),
        ("N/A", 0, ""),
    ),
    31: (
        ("N/A", 0, ""),
        ("Oui", 4, "Quarantine automatisée"),
        ("N/A", 0, ""),
    ),
    32: (
        ("N/A", 0, ""),
        ("Oui", 4, "Reporting conformité accès réseau"),
        ("N/A", 0, ""),
    ),
    34: (
        ("N/A", 0, ""),
        ("Oui", 4, "SLA FortiCare"),
        ("N/A", 0, ""),
    ),
    35: (
        ("N/A", 0, ""),
        ("Oui", 4, "Formation Fortinet NSE"),
        ("N/A", 0, ""),
    ),
    36: (
        ("N/A", 0, ""),
        ("Oui", 4, "Roadmap Fortinet NAC"),
        ("N/A", 0, ""),
    ),
    37: (
        ("N/A", 0, ""),
        ("Oui", 4, "Références clients FortiNAC"),
        ("N/A", 0, ""),
    ),
    39: (
        ("N/A", 0, ""),
        ("Oui", 4, "Licence par endpoint claire"),
        ("N/A", 0, ""),
    ),
    40: (
        ("N/A", 0, ""),
        ("Oui", 4, "Bon alignement stack Fortinet"),
        ("N/A", 0, ""),
    ),
    41: (
        ("N/A", 0, ""),
        ("Partiel", 3, "Appliances + renew"),
        ("N/A", 0, ""),
    ),
}


def fill_criteria(ws, data: dict):
    for row, triples in data.items():
        for i, (conf, note, comment) in enumerate(triples):
            base = 3 + i * 3
            ws.cell(row=row, column=base, value=conf)
            ws.cell(row=row, column=base + 1, value=note)
            ws.cell(row=row, column=base + 2, value=comment)


def main():
    wb = load_workbook(SRC)

    ctx = wb["02_Contexte"]
    # Identification offres
    ctx["B5"] = "Microsoft Sentinel"
    ctx["C5"] = "FortiSIEM"
    ctx["D5"] = "Wazuh"
    ctx["B6"] = "Non proposé (offre SIEM seule)"
    ctx["C6"] = "FortiNAC"
    ctx["D6"] = "Non proposé (offre SIEM seule)"
    ctx["B7"] = "Microsoft / partenaire"
    ctx["C7"] = "Fortinet / intégrateur"
    ctx["D7"] = "Wazuh / intégrateur OSS"
    ctx["B8"] = "Évaluation agent — à compléter"
    ctx["C8"] = "Évaluation agent — à compléter"
    ctx["D8"] = "Évaluation agent — à compléter"
    ctx["B9"] = "06/08/2026"
    ctx["C9"] = "06/08/2026"
    ctx["D9"] = "06/08/2026"
    ctx["B10"] = "À confirmer avec vendeur"
    ctx["C10"] = "À confirmer avec vendeur"
    ctx["D10"] = "À confirmer avec vendeur"
    ctx["B11"] = "—"
    ctx["C11"] = "—"
    ctx["D11"] = "—"
    ctx["B12"] = "SaaS (Azure) / hybride"
    ctx["C12"] = "On-prem / hybride"
    ctx["D12"] = "On-prem / cloud Wazuh"

    # Périmètre type (hypothèses — à ajuster)
    ctx["B16"] = 2500
    ctx["B17"] = 500
    ctx["B18"] = 150
    ctx["B19"] = 90
    ctx["B20"] = 24
    ctx["B21"] = 3
    ctx["B22"] = 800
    ctx["B23"] = "Filaire + Wi-Fi + VPN"
    ctx["B24"] = "Oui"
    ctx["B25"] = "Oui"
    ctx["B26"] = "UE / souveraineté requise"
    ctx["B27"] = "SOC interne"
    ctx["B28"] = "À définir"
    ctx["B29"] = "Q2 2027"

    # Comparaison SIEM seule (NAC hors périmètre offres A/C)
    ctx["B57"] = 70
    ctx["B58"] = 30

    fill_criteria(wb["03_SIEM_Critères"], SIEM_DATA)
    fill_criteria(wb["04_NAC_Critères"], NAC_DATA)

  # TCO indicatif 3 ans € HT — périmètre type 500 EPS / 2500 users
    tco = wb["05_TCO"]
    costs = {
        5: (180000, 120000, 45000),   # SIEM licence Y1
        6: (195000, 125000, 50000),
        7: (210000, 130000, 55000),
        8: (45000, 15000, 0),
        9: (60000, 20000, 25000),
        10: (25000, 10000, 0),
        12: (0, 85000, 0),            # NAC Y1
        13: (0, 90000, 0),
        14: (0, 95000, 0),
        15: (0, 15000, 0),
        16: (0, 40000, 0),
        17: (0, 10000, 0),
        19: (80000, 60000, 35000),    # intég SIEM
        20: (0, 45000, 0),            # intég NAC
        21: (25000, 20000, 15000),
        22: (10000, 10000, 5000),
        23: (15000, 15000, 10000),
        25: (15000, 12000, 8000),
        26: (10000, 10000, 5000),
        27: (5000, 5000, 0),
        29: (35000, 25000, 15000),
        30: (35000, 25000, 15000),
        31: (35000, 25000, 15000),
        32: (0, 0, 0),
        34: (0, 0, 25000),            # infra on-prem Wazuh
        35: (0, 0, 5000),
        36: (35000, 25000, 20000),
    }
    for row, (a, b, c) in costs.items():
        tco.cell(row=row, column=2, value=a)
        tco.cell(row=row, column=3, value=b)
        tco.cell(row=row, column=4, value=c)
        tco.cell(row=row, column=6, value="Estimation indicative — ajuster selon offres commerciales")

    syn = wb["07_Synthese"]
    syn["B5"] = "Microsoft Sentinel"
    syn["C5"] = "FortiSIEM + FortiNAC"
    syn["D5"] = "Wazuh"
    syn["B16"] = (
        "Écosystème Microsoft natif (M365, Entra, Defender). "
        "Détection avancée KQL, SOAR intégré, scalabilité cloud."
    )
    syn["C16"] = (
        "Stack Fortinet unifiée SIEM+NAC+EDR+FW. "
        "Intégration réseau excellente, déploiement on-prem possible."
    )
    syn["D16"] = (
        "Open source, souveraineté totale, TCO licence minimal. "
        "Compliance templates, flexibilité architecture."
    )
    syn["B17"] = (
        "Coût ingestion variable, courbe KQL, dépendance cloud Azure. "
        "NAC absent de l'offre."
    )
    syn["C17"] = (
        "UEBA limité, SOAR via FortiSOAR, cloud connectors moins riches. "
        "Licences multiples (SIEM+NAC+Care)."
    )
    syn["D17"] = (
        "Pas de NAC, UEBA/SOAR limités, charge opérationnelle élevée. "
        "Moins de références enterprise historiques."
    )
    syn["B18"] = "Dépendance hyperscaler, facturation ingestion"
    syn["C18"] = "Vendor lock-in stack Fortinet"
    syn["D18"] = "Compétences internes, montée en charge cluster"
    syn["B19"] = "Clarifier région Azure et coûts archive"
    syn["C19"] = "Valider périmètre FortiCare et HA"
    syn["D19"] = "Dimensionnement cluster et support commercial"
    syn["B21"] = "Offre B — FortiSIEM + FortiNAC"
    syn["A23"] = (
        "Pour un besoin SIEM+NAC intégré, Fortinet (offre B) offre le meilleur "
        "couplage technique et un score global équilibré. Microsoft Sentinel (A) "
        "domine sur cloud/M365 et détection avancée mais sans NAC et avec TCO "
        "ingestion élevé. Wazuh (C) est optimal pour souveraineté/TCO SIEM seul "
        "avec équipe technique mature."
    )
    syn["A29"] = (
        "Scénario A : Sentinel + NAC tiers (Cisco ISE / Aruba ClearPass). "
        "Scénario C : Wazuh + NAC open source ou tiers."
    )
    syn["A33"] = (
        "1. PoC 30 jours sur sources critiques | 2. Atelier technique intégrations | "
        "3. Négociation licences ingestion (A) / FortiCare bundle (B) | "
        "4. Audit dimensionnement Wazuh (C)"
    )

    wb.save(OUT)
    print(f"Fichier rempli : {OUT}")


if __name__ == "__main__":
    main()
