#!/usr/bin/env python3
"""
Audit de configuration FortiGate 601F
=====================================
Analyse un fichier de configuration CLI exporté (ou une config récupérée via API)
et produit un rapport de conformité / durcissement.

Usage:
  python3 fg601f_audit.py -c config.conf
  python3 fg601f_audit.py -c config.conf -o rapport.json --format json
  python3 fg601f_audit.py -c config.conf --format html -o rapport.html
  python3 fg601f_audit.py --api https://192.168.1.99 --token <API_TOKEN> --vdom root

Auteur : Expert Fortinet — Audit 601F
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Modèle de finding
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"CRITIQUE": 0, "ELEVE": 1, "MOYEN": 2, "FAIBLE": 3, "INFO": 4}


@dataclass
class Finding:
    id: str
    categorie: str
    severite: str
    titre: str
    detail: str
    recommandation: str
    statut: str = "FAIL"  # FAIL | PASS | WARN | INFO
    preuve: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuditReport:
    modele: str = "inconnu"
    hostname: str = "inconnu"
    version: str = "inconnue"
    serial: str = "inconnu"
    vdom_mode: str = "inconnu"
    date_audit: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    findings: list[Finding] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for f in self.findings:
            if f.statut == "FAIL":
                counts[f.severite] += 1
            counts[f"STATUT_{f.statut}"] += 1
        return dict(counts)


# ---------------------------------------------------------------------------
# Parseur de configuration FortiOS CLI
# ---------------------------------------------------------------------------

class FortiConfig:
    """Parseur léger de blocs `config ... end` FortiOS."""

    def __init__(self, text: str):
        self.raw = text
        self.lines = text.splitlines()
        self.global_sets = self._parse_global_sets()
        self.blocks = self._parse_blocks()

    def _parse_global_sets(self) -> dict[str, str]:
        """Extrait les `set key value` hors contextes edit (niveau racine des blocs)."""
        return {}

    def _parse_blocks(self) -> dict[str, list[dict[str, Any]]]:
        """
        Retourne un dict path -> liste d'objets.
        Ex: 'system admin' -> [{name: admin, sets: {...}}, ...]
             'firewall policy' -> [{edit: 1, sets: {...}}, ...]
        """
        result: dict[str, list[dict[str, Any]]] = defaultdict(list)
        stack: list[str] = []
        current_obj: dict[str, Any] | None = None
        current_path = ""

        for raw_line in self.lines:
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue

            if line.startswith("config "):
                path = line[len("config ") :].strip()
                stack.append(path)
                current_path = " ".join(stack)
                current_obj = None
                continue

            if line == "end":
                if current_obj is not None and current_path:
                    result[current_path].append(current_obj)
                    current_obj = None
                if stack:
                    stack.pop()
                current_path = " ".join(stack)
                continue

            if line == "next":
                if current_obj is not None and current_path:
                    result[current_path].append(current_obj)
                current_obj = None
                continue

            if line.startswith("edit "):
                if current_obj is not None and current_path:
                    result[current_path].append(current_obj)
                key = line[len("edit ") :].strip().strip('"')
                current_obj = {"edit": key, "sets": {}}
                continue

            if line.startswith("set "):
                # set key value(s)
                rest = line[len("set ") :].strip()
                parts = self._split_cli(rest)
                if not parts:
                    continue
                key = parts[0]
                value = " ".join(parts[1:]) if len(parts) > 1 else ""
                if current_obj is not None:
                    current_obj["sets"][key] = value
                else:
                    # set au niveau du bloc (sans edit) → objet virtuel "_block"
                    block_objs = result[current_path]
                    if not block_objs or block_objs[-1].get("edit") != "_block":
                        result[current_path].append({"edit": "_block", "sets": {}})
                    result[current_path][-1]["sets"][key] = value
                continue

            if line.startswith("unset "):
                key = line[len("unset ") :].strip()
                if current_obj is not None:
                    current_obj["sets"][key] = None
                continue

        return result

    @staticmethod
    def _split_cli(s: str) -> list[str]:
        """Découpe en tokens en respectant les guillemets."""
        return re.findall(r'"([^"]*)"|(\S+)', s) and [
            m[0] if m[0] else m[1] for m in re.findall(r'"([^"]*)"|(\S+)', s)
        ]

    def get_block(self, path: str) -> list[dict[str, Any]]:
        return self.blocks.get(path, [])

    def get_block_sets(self, path: str) -> dict[str, str]:
        objs = self.get_block(path)
        for o in objs:
            if o.get("edit") == "_block":
                return {k: v for k, v in o.get("sets", {}).items() if v is not None}
        # fallback: fusionner tous les sets si un seul objet
        if len(objs) == 1:
            return {k: v for k, v in objs[0].get("sets", {}).items() if v is not None}
        merged: dict[str, str] = {}
        for o in objs:
            for k, v in o.get("sets", {}).items():
                if v is not None:
                    merged[k] = v
        return merged

    def find_set_anywhere(self, key: str) -> list[tuple[str, str, str]]:
        """Retourne (path, edit, value) pour toutes les occurrences d'une clé set."""
        hits = []
        for path, objs in self.blocks.items():
            for o in objs:
                if key in o.get("sets", {}):
                    hits.append((path, str(o.get("edit", "")), str(o["sets"][key])))
        return hits

    def regex_search(self, pattern: str, flags: int = re.IGNORECASE) -> list[str]:
        rx = re.compile(pattern, flags)
        return [ln for ln in self.lines if rx.search(ln)]


# ---------------------------------------------------------------------------
# Collecte métadonnées 601F
# ---------------------------------------------------------------------------

def extract_metadata(cfg: FortiConfig, report: AuditReport) -> None:
    # Hostname
    for path in ("system global",):
        sets = cfg.get_block_sets(path)
        if "hostname" in sets:
            report.hostname = sets["hostname"].strip('"')
        if "alias" in sets and report.hostname == "inconnu":
            report.hostname = sets["alias"].strip('"')

    # Version / modèle souvent en commentaires d'export
    for ln in cfg.lines[:80]:
        m = re.search(r"config-version=(\S+)", ln)
        if m:
            # ex: FG6H1F-7.2.8-FW-buildxxxx
            report.meta["config_version"] = m.group(1)
            parts = m.group(1).split("-")
            if parts:
                report.modele = parts[0]
            if len(parts) > 1:
                report.version = parts[1]
        m = re.search(r"#\s*FortiGate-(\S+)", ln)
        if m:
            report.modele = m.group(1)
        m = re.search(r"serial(?:Number)?[=:\s]+(\S+)", ln, re.I)
        if m:
            report.serial = m.group(1).strip('"')

    # Détection 601F dans le texte
    if re.search(r"601[Ff]|FG6H1F|FortiGate-601F", cfg.raw):
        report.modele = "FortiGate-601F"
        report.meta["modele_detecte"] = True
    else:
        report.meta["modele_detecte"] = False
        report.add(
            Finding(
                id="META-001",
                categorie="Inventaire",
                severite="MOYEN",
                titre="Modèle 601F non confirmé dans la configuration",
                detail="Aucune mention explicite de FortiGate-601F / FG6H1F trouvée.",
                recommandation="Vérifier `get system status` et confirmer le modèle avant durcissement matériel-spécifique.",
                statut="WARN",
            )
        )

    # VDOM
    sets = cfg.get_block_sets("system global")
    if sets.get("vdom-mode"):
        report.vdom_mode = sets["vdom-mode"]
    elif cfg.get_block("vdom"):
        report.vdom_mode = "multi-vdom (détecté)"
    else:
        report.vdom_mode = "no-vdom / root"


# ---------------------------------------------------------------------------
# Checks d'audit
# ---------------------------------------------------------------------------

def check_admin_access(cfg: FortiConfig, report: AuditReport) -> None:
    cat = "Accès administration"

    # HTTP admin désactivé
    sets = cfg.get_block_sets("system global")
    admin_https = sets.get("admin-https-redirect", "enable")
    admin_port = sets.get("admin-port", "80")
    admin_sport = sets.get("admin-sport", "443")
    admin_ssh = sets.get("admin-ssh-port", "22")

    if admin_port != "0" and "set admin-port 0" not in cfg.raw and not re.search(
        r"set admin-port\s+0\b", cfg.raw
    ):
        # Sur FortiOS, désactiver HTTP = souvent admin-port non exposé + allowaccess sans http
        pass

    # Interfaces: allowaccess http / telnet
    ifaces = cfg.get_block("system interface")
    http_ifaces = []
    telnet_ifaces = []
    open_mgmt = []
    for iface in ifaces:
        if iface.get("edit") == "_block":
            continue
        name = iface["edit"]
        allow = iface.get("sets", {}).get("allowaccess", "")
        tokens = allow.replace('"', "").split()
        if "http" in tokens:
            http_ifaces.append(name)
        if "telnet" in tokens:
            telnet_ifaces.append(name)
        risky = [t for t in tokens if t in ("http", "telnet", "ping") or t == "https" or t == "ssh"]
        # HTTPS/SSH sur interface WAN
        role = iface.get("sets", {}).get("role", "")
        ip = iface.get("sets", {}).get("ip", "")
        if ("https" in tokens or "ssh" in tokens) and (
            role == "wan" or name.lower() in ("wan", "wan1", "wan2", "port1")
            or "0.0.0.0" in (iface.get("sets", {}).get("secondary-IP", "") or "")
        ):
            open_mgmt.append(f"{name} allowaccess={allow}")

        # Toute interface avec https/ssh sans trusted hosts sera revue plus bas
        if "https" in tokens or "ssh" in tokens:
            open_mgmt.append(f"{name}: {allow}")

    if http_ifaces:
        report.add(
            Finding(
                id="ADM-001",
                categorie=cat,
                severite="CRITIQUE",
                titre="Accès HTTP (non chiffré) activé sur interface(s)",
                detail=f"Interfaces: {', '.join(http_ifaces)}",
                recommandation="Retirer `http` de `allowaccess`. Forcer HTTPS uniquement.",
                preuve=", ".join(http_ifaces),
            )
        )
    else:
        report.add(
            Finding(
                id="ADM-001",
                categorie=cat,
                severite="INFO",
                titre="Aucun allowaccess HTTP détecté",
                detail="Pas d'interface avec http dans allowaccess.",
                recommandation="Conserver cet état.",
                statut="PASS",
            )
        )

    if telnet_ifaces:
        report.add(
            Finding(
                id="ADM-002",
                categorie=cat,
                severite="CRITIQUE",
                titre="Telnet activé sur interface(s)",
                detail=f"Interfaces: {', '.join(telnet_ifaces)}",
                recommandation="Désactiver telnet. Utiliser SSH uniquement.",
                preuve=", ".join(telnet_ifaces),
            )
        )
    else:
        report.add(
            Finding(
                id="ADM-002",
                categorie=cat,
                severite="INFO",
                titre="Telnet non exposé",
                detail="Aucune interface avec telnet.",
                recommandation="Conserver cet état.",
                statut="PASS",
            )
        )

    # Trusted hosts sur admins
    admins = [a for a in cfg.get_block("system admin") if a.get("edit") != "_block"]
    weak_admins = []
    no_trust = []
    no_2fa = []
    for adm in admins:
        name = adm["edit"]
        s = adm.get("sets", {})
        trust_keys = [k for k in s if k.startswith("trusthost")]
        if not trust_keys:
            no_trust.append(name)
        else:
            for tk in trust_keys:
                if s.get(tk, "").startswith("0.0.0.0") or s.get(tk, "").startswith("::/0"):
                    no_trust.append(f"{name}({tk}=any)")
        if s.get("two-factor") in (None, "disable", ""):
            # two-factor absent = souvent disable
            if "two-factor" not in s or s.get("two-factor") == "disable":
                no_2fa.append(name)
        # accprofile super_admin
        if s.get("accprofile") == "super_admin":
            weak_admins.append(name)

    if no_trust:
        report.add(
            Finding(
                id="ADM-003",
                categorie=cat,
                severite="ELEVE",
                titre="Admins sans trusted hosts restrictifs",
                detail=f"Comptes concernés: {', '.join(dict.fromkeys(no_trust))}",
                recommandation="Configurer `trusthost1` (et suivants) sur des sous-réseaux d'administration dédiés.",
                preuve=", ".join(dict.fromkeys(no_trust)),
            )
        )
    else:
        report.add(
            Finding(
                id="ADM-003",
                categorie=cat,
                severite="INFO",
                titre="Trusted hosts présents sur les admins",
                detail=f"{len(admins)} compte(s) admin analysé(s).",
                recommandation="Vérifier périodiquement les plages autorisées.",
                statut="PASS",
            )
        )

    if no_2fa:
        report.add(
            Finding(
                id="ADM-004",
                categorie=cat,
                severite="ELEVE",
                titre="Authentification à 2 facteurs absente / désactivée",
                detail=f"Comptes: {', '.join(no_2fa)}",
                recommandation="Activer FortiToken / MFA (`set two-factor fortitoken`) et `set multi-factor-authentication mandatory` (system global).",
                preuve=", ".join(no_2fa),
            )
        )
    else:
        report.add(
            Finding(
                id="ADM-004",
                categorie=cat,
                severite="INFO",
                titre="2FA activée sur les comptes admin",
                detail="Tous les admins ont un two-factor configuré.",
                recommandation="Conserver MFA obligatoire.",
                statut="PASS",
            )
        )

    mfa = sets.get("multi-factor-authentication", "optional")
    if mfa != "mandatory":
        report.add(
            Finding(
                id="ADM-005",
                categorie=cat,
                severite="MOYEN",
                titre="MFA globale non obligatoire",
                detail=f"multi-factor-authentication = {mfa}",
                recommandation="`config system global` → `set multi-factor-authentication mandatory`.",
                preuve=f"multi-factor-authentication={mfa}",
            )
        )
    else:
        report.add(
            Finding(
                id="ADM-005",
                categorie=cat,
                severite="INFO",
                titre="MFA globale obligatoire",
                detail="multi-factor-authentication=mandatory",
                recommandation="OK.",
                statut="PASS",
            )
        )

    # Password policy
    pp = cfg.get_block_sets("system password-policy")
    if not pp or pp.get("status") == "disable":
        report.add(
            Finding(
                id="ADM-006",
                categorie=cat,
                severite="ELEVE",
                titre="Politique de mots de passe désactivée ou absente",
                detail="system password-policy non durcie.",
                recommandation="Activer password-policy (min 12, upper/lower/number/special, expire).",
            )
        )
    else:
        min_len = int(pp.get("minimum-length", "8") or "8")
        if min_len < 12:
            report.add(
                Finding(
                    id="ADM-006",
                    categorie=cat,
                    severite="MOYEN",
                    titre="Longueur minimale de mot de passe insuffisante",
                    detail=f"minimum-length={min_len}",
                    recommandation="Fixer minimum-length à 12 ou plus.",
                    preuve=f"minimum-length={min_len}",
                )
            )
        else:
            report.add(
                Finding(
                    id="ADM-006",
                    categorie=cat,
                    severite="INFO",
                    titre="Politique de mots de passe active",
                    detail=f"status={pp.get('status')}, minimum-length={min_len}",
                    recommandation="OK.",
                    statut="PASS",
                )
            )

    # Ports admin non standards (bonne pratique)
    if admin_sport == "443":
        report.add(
            Finding(
                id="ADM-007",
                categorie=cat,
                severite="FAIBLE",
                titre="Port HTTPS admin par défaut (443)",
                detail=f"admin-sport={admin_sport}",
                recommandation="Envisager un port non standard + local-in-policy restrictive.",
                preuve=f"admin-sport={admin_sport}",
                statut="WARN",
            )
        )

    if admin_ssh == "22":
        report.add(
            Finding(
                id="ADM-008",
                categorie=cat,
                severite="FAIBLE",
                titre="Port SSH admin par défaut (22)",
                detail=f"admin-ssh-port={admin_ssh}",
                recommandation="Changer le port SSH et restreindre via trusted hosts / local-in.",
                preuve=f"admin-ssh-port={admin_ssh}",
                statut="WARN",
            )
        )

    # idle timeout
    idle = sets.get("admintimeout", "5")
    try:
        idle_i = int(idle)
    except ValueError:
        idle_i = 5
    if idle_i > 15:
        report.add(
            Finding(
                id="ADM-009",
                categorie=cat,
                severite="MOYEN",
                titre="Timeout admin trop élevé",
                detail=f"admintimeout={idle_i} min",
                recommandation="Réduire admintimeout ≤ 10–15 minutes.",
                preuve=f"admintimeout={idle_i}",
            )
        )
    else:
        report.add(
            Finding(
                id="ADM-009",
                categorie=cat,
                severite="INFO",
                titre="Timeout admin acceptable",
                detail=f"admintimeout={idle_i} min",
                recommandation="OK.",
                statut="PASS",
            )
        )


def check_snmp(cfg: FortiConfig, report: AuditReport) -> None:
    cat = "SNMP / Supervision"
    communities = [c for c in cfg.get_block("system snmp community") if c.get("edit") != "_block"]
    users = [u for u in cfg.get_block("system snmp user") if u.get("edit") != "_block"]

    weak = []
    for c in communities:
        s = c.get("sets", {})
        name = c["edit"]
        if s.get("status", "enable") == "disable":
            continue
        # hosts
        # SNMPv1/v2c = community
        weak.append(name)
        if s.get("query-v1-status") == "enable" or s.get("query-v2c-status") == "enable":
            weak.append(f"{name} (v1/v2c query enable)")

    if weak:
        report.add(
            Finding(
                id="SNMP-001",
                categorie=cat,
                severite="ELEVE",
                titre="SNMP v1/v2c (community) détecté",
                detail=f"Communities: {', '.join(dict.fromkeys(weak))}",
                recommandation="Migrer vers SNMPv3 (system snmp user) avec authPriv. Désactiver les communities.",
                preuve=", ".join(dict.fromkeys(weak)),
            )
        )
    elif users:
        report.add(
            Finding(
                id="SNMP-001",
                categorie=cat,
                severite="INFO",
                titre="SNMPv3 utilisateurs présents, pas de community active évidente",
                detail=f"{len(users)} user(s) SNMP.",
                recommandation="Vérifier security-level = authPriv.",
                statut="PASS",
            )
        )
    else:
        report.add(
            Finding(
                id="SNMP-001",
                categorie=cat,
                severite="INFO",
                titre="SNMP non configuré ou inactif",
                detail="Aucune community/user SNMP trouvée.",
                recommandation="Si supervision nécessaire, utiliser SNMPv3 uniquement.",
                statut="PASS",
            )
        )


def check_ntp_dns(cfg: FortiConfig, report: AuditReport) -> None:
    cat = "Temps & DNS"
    ntp = cfg.get_block_sets("system ntp")
    if not ntp or ntp.get("ntpsync") == "disable":
        report.add(
            Finding(
                id="NTP-001",
                categorie=cat,
                severite="ELEVE",
                titre="Synchronisation NTP absente ou désactivée",
                detail="system ntp non conforme.",
                recommandation="Activer NTP vers des serveurs internes de confiance (ou FortiGuard).",
            )
        )
    else:
        report.add(
            Finding(
                id="NTP-001",
                categorie=cat,
                severite="INFO",
                titre="NTP activé",
                detail=f"ntpsync={ntp.get('ntpsync', 'enable')}",
                recommandation="Préférer des serveurs NTP internes authentifiés si possible.",
                statut="PASS",
            )
        )

    dns = cfg.get_block_sets("system dns")
    primary = dns.get("primary", "")
    if primary in ("", "0.0.0.0"):
        report.add(
            Finding(
                id="DNS-001",
                categorie=cat,
                severite="MOYEN",
                titre="DNS primaire non défini",
                detail="system dns primary manquant.",
                recommandation="Configurer des DNS internes ou FortiGuard DNS.",
            )
        )
    else:
        report.add(
            Finding(
                id="DNS-001",
                categorie=cat,
                severite="INFO",
                titre="DNS configuré",
                detail=f"primary={primary}, secondary={dns.get('secondary', '-')}",
                recommandation="OK.",
                statut="PASS",
            )
        )


def check_logging(cfg: FortiConfig, report: AuditReport) -> None:
    cat = "Journalisation"
    syslog = [s for s in cfg.get_block("log syslogd setting") if True]
    syslog_sets = cfg.get_block_sets("log syslogd setting")
    faz = cfg.get_block_sets("log fortianalyzer setting")

    disk = cfg.get_block_sets("log disk setting")
    memory = cfg.get_block_sets("log memory setting")

    if syslog_sets.get("status") == "enable" or faz.get("status") == "enable":
        dest = []
        if syslog_sets.get("status") == "enable":
            dest.append(f"syslog → {syslog_sets.get('server', '?')}")
        if faz.get("status") == "enable":
            dest.append(f"FortiAnalyzer → {faz.get('server', '?')}")
        report.add(
            Finding(
                id="LOG-001",
                categorie=cat,
                severite="INFO",
                titre="Export de logs centralisé activé",
                detail="; ".join(dest),
                recommandation="Vérifier chiffrement / fiabilité (reliable) et rétention.",
                statut="PASS",
                preuve="; ".join(dest),
            )
        )
    else:
        report.add(
            Finding(
                id="LOG-001",
                categorie=cat,
                severite="ELEVE",
                titre="Pas d'export syslog / FortiAnalyzer",
                detail="log syslogd / fortianalyzer non enable.",
                recommandation="Configurer un SIEM / FortiAnalyzer (ex. Sentinel) pour centraliser les logs 601F.",
            )
        )

    # Event logging global
    event = cfg.get_block_sets("log eventfilter")
    # traffic log on policies checked elsewhere


def check_firewall_policies(cfg: FortiConfig, report: AuditReport) -> None:
    cat = "Politiques firewall"
    policies = [p for p in cfg.get_block("firewall policy") if p.get("edit") != "_block"]

    any_any = []
    no_log = []
    no_utm = []
    disabled = 0
    enabled = 0

    for p in policies:
        pid = p["edit"]
        s = p.get("sets", {})
        if s.get("status") == "disable":
            disabled += 1
            continue
        enabled += 1
        src = s.get("srcaddr", "")
        dst = s.get("dstaddr", "")
        svc = s.get("service", "")
        action = s.get("action", "deny")
        srcintf = s.get("srcintf", "")
        dstintf = s.get("dstintf", "")

        if action == "accept" and (
            ("all" in src.split() and "all" in dst.split())
            or (src.strip('"') == "all" and dst.strip('"') == "all")
        ):
            if "ALL" in svc.upper().split() or svc.strip('"').upper() == "ALL":
                any_any.append(pid)

        log = s.get("logtraffic", "utm")
        if action == "accept" and log in ("disable", ""):
            no_log.append(pid)

        # UTM profiles
        utm_keys = [
            "utm-status",
            "av-profile",
            "ips-sensor",
            "application-list",
            "webfilter-profile",
            "ssl-ssh-profile",
            "dnsfilter-profile",
            "file-filter-profile",
        ]
        has_utm = s.get("utm-status") == "enable" or any(
            k in s and s[k] not in ("", None) for k in utm_keys[1:]
        )
        # Policies WAN->LAN / outbound sans UTM
        if action == "accept" and not has_utm:
            # ignorer IPsec pure parfois
            if "ipsec" not in (s.get("name", "") or "").lower():
                no_utm.append(pid)

    report.meta["policies_enabled"] = enabled
    report.meta["policies_disabled"] = disabled

    if any_any:
        report.add(
            Finding(
                id="POL-001",
                categorie=cat,
                severite="CRITIQUE",
                titre="Politique(s) any-any-all ACCEPT détectée(s)",
                detail=f"Policy ID: {', '.join(any_any)}",
                recommandation="Supprimer / restreindre (least privilege). Interdire any/any/ALL en production.",
                preuve=", ".join(any_any),
            )
        )
    else:
        report.add(
            Finding(
                id="POL-001",
                categorie=cat,
                severite="INFO",
                titre="Pas de politique any-any-ALL ACCEPT",
                detail=f"{enabled} politique(s) active(s) analysée(s).",
                recommandation="OK.",
                statut="PASS",
            )
        )

    if no_log:
        report.add(
            Finding(
                id="POL-002",
                categorie=cat,
                severite="MOYEN",
                titre="Politiques ACCEPT sans journalisation",
                detail=f"Policy ID: {', '.join(no_log[:30])}{'...' if len(no_log) > 30 else ''}",
                recommandation="`set logtraffic all` ou `utm` sur toutes les politiques accept.",
                preuve=", ".join(no_log[:30]),
            )
        )
    else:
        report.add(
            Finding(
                id="POL-002",
                categorie=cat,
                severite="INFO",
                titre="Journalisation présente sur les politiques ACCEPT",
                detail="Aucune politique accept sans logtraffic détectée.",
                recommandation="OK.",
                statut="PASS",
            )
        )

    if no_utm:
        report.add(
            Finding(
                id="POL-003",
                categorie=cat,
                severite="ELEVE",
                titre="Politiques ACCEPT sans profil de sécurité (UTM)",
                detail=f"{len(no_utm)} politique(s) sans AV/IPS/AppCtrl/WebFilter/SSL. Ex: {', '.join(no_utm[:20])}",
                recommandation="Activer utm-status et attacher IPS + AV + App Control (+ SSL inspection) selon le flux.",
                preuve=", ".join(no_utm[:20]),
            )
        )
    else:
        report.add(
            Finding(
                id="POL-003",
                categorie=cat,
                severite="INFO",
                titre="Profils UTM présents sur les ACCEPT",
                detail="OK ou aucune politique accept sans UTM.",
                recommandation="OK.",
                statut="PASS",
            )
        )

    if disabled > 20:
        report.add(
            Finding(
                id="POL-004",
                categorie=cat,
                severite="FAIBLE",
                titre="Nombre élevé de politiques désactivées",
                detail=f"{disabled} politiques disabled.",
                recommandation="Nettoyer les politiques obsolètes (hygiène config 601F).",
                statut="WARN",
            )
        )


def check_ssl_inspection(cfg: FortiConfig, report: AuditReport) -> None:
    cat = "Inspection SSL/SSH"
    profiles = [p for p in cfg.get_block("firewall ssl-ssh-profile") if p.get("edit") != "_block"]
    if not profiles:
        report.add(
            Finding(
                id="SSL-001",
                categorie=cat,
                severite="MOYEN",
                titre="Aucun profil SSL/SSH inspection trouvé",
                detail="firewall ssl-ssh-profile vide.",
                recommandation="Créer un profil certificate-inspection a minima, deep-inspection pour flux critiques.",
            )
        )
        return

    only_disable = True
    for p in profiles:
        s = p.get("sets", {})
        # nested configs hard to parse fully — heuristic on raw around profile
        name = p["edit"]
        if name.lower() not in ("no-inspection", "deep-inspection", "certificate-inspection", "custom-deep-inspection"):
            only_disable = False
        if name.lower() == "deep-inspection" or "deep" in name.lower():
            only_disable = False

    # Check if policies reference ssl-ssh-profile
    policies = [p for p in cfg.get_block("firewall policy") if p.get("edit") != "_block"]
    used = []
    for p in policies:
        if p.get("sets", {}).get("status") == "disable":
            continue
        prof = p.get("sets", {}).get("ssl-ssh-profile")
        if prof and prof not in ("", "no-inspection"):
            used.append((p["edit"], prof))

    if not used:
        report.add(
            Finding(
                id="SSL-001",
                categorie=cat,
                severite="ELEVE",
                titre="SSL inspection non appliquée aux politiques",
                detail=f"{len(profiles)} profil(s) existent mais non référencés (ou no-inspection).",
                recommandation="Attacher certificate-inspection ou deep-inspection aux politiques Internet.",
            )
        )
    else:
        report.add(
            Finding(
                id="SSL-001",
                categorie=cat,
                severite="INFO",
                titre="SSL inspection référencée dans des politiques",
                detail=f"{len(used)} politique(s) avec ssl-ssh-profile. Ex: {used[:5]}",
                recommandation="Vérifier deep-inspection sur flux métiers sensibles + exceptions DoH/cert pinning.",
                statut="PASS",
                preuve=str(used[:10]),
            )
        )


def check_vpn(cfg: FortiConfig, report: AuditReport) -> None:
    cat = "VPN"
    ssl_settings = cfg.get_block_sets("vpn ssl settings")
    if ssl_settings:
        status_lines = cfg.regex_search(r"config vpn ssl settings")
        port = ssl_settings.get("port", "443")
        tunnel = ssl_settings.get("tunnel-ip-pools") or ssl_settings.get("tunnel-ip-pool", "")
        algo = ssl_settings.get("algorithm", "")
        # SSL VPN souvent enable si bloc présent avec source-interface
        src_intf = ssl_settings.get("source-interface", "")
        if src_intf or tunnel:
            report.add(
                Finding(
                    id="VPN-001",
                    categorie=cat,
                    severite="MOYEN",
                    titre="SSL-VPN configuré",
                    detail=f"port={port}, source-interface={src_intf or '-'}, algorithm={algo or 'default'}",
                    recommandation=(
                        "Restreindre source-address, imposer MFA, certificats valides (pas default), "
                        "désactiver SSL-VPN si IPsec/ZTNA suffit (recommandation Fortinet récente)."
                    ),
                    preuve=f"port={port}",
                    statut="WARN",
                )
            )
            if port == "443":
                report.add(
                    Finding(
                        id="VPN-002",
                        categorie=cat,
                        severite="FAIBLE",
                        titre="SSL-VPN sur port 443",
                        detail="Collision possible avec admin HTTPS.",
                        recommandation="Séparer ports admin / SSL-VPN ; restreindre local-in.",
                        statut="WARN",
                    )
                )
    else:
        report.add(
            Finding(
                id="VPN-001",
                categorie=cat,
                severite="INFO",
                titre="SSL-VPN non configuré (ou absent du dump)",
                detail="Pas de vpn ssl settings.",
                recommandation="OK si accès distant via IPsec / SASE / ZTNA.",
                statut="PASS",
            )
        )

    # IPsec phase1
    p1 = [p for p in cfg.get_block("vpn ipsec phase1-interface") if p.get("edit") != "_block"]
    weak_ike = []
    for t in p1:
        s = t.get("sets", {})
        prop = s.get("proposal", "")
        dh = s.get("dhgrp", "")
        if "des" in prop.lower() or "md5" in prop.lower() or "sha1" in prop.lower():
            weak_ike.append(t["edit"])
        if dh and any(x in dh.split() for x in ("1", "2", "5")):
            weak_ike.append(f"{t['edit']}(dhgrp faible)")

    if weak_ike:
        report.add(
            Finding(
                id="VPN-003",
                categorie=cat,
                severite="ELEVE",
                titre="IPsec Phase1 avec crypto faible",
                detail=f"Tunnels: {', '.join(dict.fromkeys(weak_ike))}",
                recommandation="Utiliser AES256-GCM/SHA256+, DH19/20/21. Désactiver DES/3DES/MD5/SHA1/DH1-5.",
                preuve=", ".join(dict.fromkeys(weak_ike)),
            )
        )
    elif p1:
        report.add(
            Finding(
                id="VPN-003",
                categorie=cat,
                severite="INFO",
                titre="IPsec Phase1 sans crypto faible évidente",
                detail=f"{len(p1)} tunnel(s) phase1-interface.",
                recommandation="Valider proposals et PFS.",
                statut="PASS",
            )
        )


def check_security_profiles(cfg: FortiConfig, report: AuditReport) -> None:
    cat = "Profils de sécurité"
    ips = [p for p in cfg.get_block("ips sensor") if p.get("edit") != "_block"]
    av = [p for p in cfg.get_block("antivirus profile") if p.get("edit") != "_block"]
    app = [p for p in cfg.get_block("application list") if p.get("edit") != "_block"]
    wf = [p for p in cfg.get_block("webfilter profile") if p.get("edit") != "_block"]

    def _check(name: str, fid: str, objs: list) -> None:
        if not objs:
            report.add(
                Finding(
                    id=fid,
                    categorie=cat,
                    severite="ELEVE",
                    titre=f"Aucun {name} défini",
                    detail=f"Bloc {name} vide.",
                    recommandation=f"Créer et appliquer un {name} (mode block) sur les flux Internet.",
                )
            )
        else:
            report.add(
                Finding(
                    id=fid,
                    categorie=cat,
                    severite="INFO",
                    titre=f"{name} présent ({len(objs)})",
                    detail=f"Profils: {', '.join(o['edit'] for o in objs[:8])}",
                    recommandation="Vérifier action=block et mises à jour FortiGuard.",
                    statut="PASS",
                )
            )

    _check("IPS sensor", "UTM-001", ips)
    _check("Antivirus profile", "UTM-002", av)
    _check("Application list", "UTM-003", app)
    _check("Webfilter profile", "UTM-004", wf)

    # Autoupdate
    au = cfg.get_block_sets("system autoupdate schedule") or cfg.get_block_sets("system fortiguard")
    fg = cfg.get_block_sets("system fortiguard")
    if fg.get("update-server-location") or "fortiguard" in cfg.raw.lower():
        report.add(
            Finding(
                id="UTM-005",
                categorie=cat,
                severite="INFO",
                titre="FortiGuard référencé dans la configuration",
                detail=str({k: fg[k] for k in list(fg)[:6]}) if fg else "références textuelles",
                recommandation="Vérifier licences FortiGuard (AV/IPS/WF) actives sur le 601F.",
                statut="PASS",
            )
        )


def check_ha_backup(cfg: FortiConfig, report: AuditReport) -> None:
    cat = "HA & résilience"
    ha = cfg.get_block_sets("system ha")
    mode = ha.get("mode", "standalone")
    if mode in ("a-p", "a-a"):
        report.add(
            Finding(
                id="HA-001",
                categorie=cat,
                severite="INFO",
                titre=f"HA configurée (mode={mode})",
                detail=f"group-name={ha.get('group-name', '-')}, password={'***' if ha.get('password') else 'ABSENT'}",
                recommandation="Vérifier moniteurs hbdev, session-pickup, firmware alignés (cluster 601F).",
                statut="PASS" if ha.get("password") else "WARN",
            )
        )
        if not ha.get("password"):
            report.add(
                Finding(
                    id="HA-002",
                    categorie=cat,
                    severite="CRITIQUE",
                    titre="Mot de passe HA manquant",
                    detail="system ha password absent.",
                    recommandation="Définir un password HA fort.",
                )
            )
    else:
        report.add(
            Finding(
                id="HA-001",
                categorie=cat,
                severite="MOYEN",
                titre="Pas de HA (standalone)",
                detail=f"mode={mode}",
                recommandation="Pour un 601F en production critique, envisager un cluster A-P.",
                statut="WARN",
            )
        )


def check_local_in_and_services(cfg: FortiConfig, report: AuditReport) -> None:
    cat = "Services exposés"
    # Explicit allow of WAN management already partially done
    # Check automation / rest-api
    api = cfg.get_block_sets("system api-user") or {}
    api_users = [u for u in cfg.get_block("system api-user") if u.get("edit") != "_block"]
    if api_users:
        no_trust = [u["edit"] for u in api_users if not any(
            k.startswith("trusthost") for k in u.get("sets", {})
        )]
        if no_trust:
            report.add(
                Finding(
                    id="API-001",
                    categorie=cat,
                    severite="ELEVE",
                    titre="API users sans trusthost",
                    detail=f"Users: {', '.join(no_trust)}",
                    recommandation="Restreindre trusthost et accprofile minimal pour les comptes REST API.",
                    preuve=", ".join(no_trust),
                )
            )
        else:
            report.add(
                Finding(
                    id="API-001",
                    categorie=cat,
                    severite="INFO",
                    titre="API users avec trusthost",
                    detail=f"{len(api_users)} compte(s).",
                    recommandation="OK.",
                    statut="PASS",
                )
            )

    # VIP / port-forward
    vips = [v for v in cfg.get_block("firewall vip") if v.get("edit") != "_block"]
    if vips:
        report.add(
            Finding(
                id="VIP-001",
                categorie=cat,
                severite="MOYEN",
                titre=f"{len(vips)} VIP / publication(s) détectée(s)",
                detail=f"Ex: {', '.join(v['edit'] for v in vips[:10])}",
                recommandation="Revue: minimiser les publications, IPS sur politiques VIP, geo/IP restriction.",
                statut="WARN",
                preuve=", ".join(v["edit"] for v in vips[:15]),
            )
        )


def check_601f_specific(cfg: FortiConfig, report: AuditReport) -> None:
    """Contrôles orientés plateforme FortiGate 601F (NP7, perf, interfaces)."""
    cat = "Spécifique 601F"

    report.add(
        Finding(
            id="FG601F-001",
            categorie=cat,
            severite="INFO",
            titre="Plateforme cible FortiGate 601F (NP7)",
            detail=(
                "Le 601F dispose d'accélération NP7. Vérifier que le offloading n'est pas "
                "involontairement désactivé et que les profils UTM sont dimensionnés."
            ),
            recommandation=(
                "Contrôler `config system npu` / `auto-asic-offload` sur politiques ; "
                "monitorer CPU/NP via `get hardware npu np7 status` en opérationnel."
            ),
            statut="INFO",
        )
    )

    # Offloading disabled on many policies?
    policies = [p for p in cfg.get_block("firewall policy") if p.get("edit") != "_block"]
    no_offload = [
        p["edit"]
        for p in policies
        if p.get("sets", {}).get("auto-asic-offload") == "disable"
        and p.get("sets", {}).get("status") != "disable"
    ]
    if len(no_offload) > 5:
        report.add(
            Finding(
                id="FG601F-002",
                categorie=cat,
                severite="MOYEN",
                titre="ASIC offload désactivé sur de nombreuses politiques",
                detail=f"{len(no_offload)} politiques avec auto-asic-offload=disable.",
                recommandation="Réactiver l'offload sauf besoin diagnostic ; impact perf 601F.",
                preuve=", ".join(no_offload[:20]),
            )
        )

    # Sessions helpers / conservative
    sets = cfg.get_block_sets("system global")
    if sets.get("anti-replay") == "disable":
        report.add(
            Finding(
                id="FG601F-003",
                categorie=cat,
                severite="ELEVE",
                titre="Anti-replay désactivé",
                detail="system global anti-replay=disable",
                recommandation="Réactiver anti-replay sauf cas de support documenté.",
            )
        )


def run_all_checks(cfg: FortiConfig) -> AuditReport:
    report = AuditReport()
    extract_metadata(cfg, report)
    check_admin_access(cfg, report)
    check_snmp(cfg, report)
    check_ntp_dns(cfg, report)
    check_logging(cfg, report)
    check_firewall_policies(cfg, report)
    check_ssl_inspection(cfg, report)
    check_vpn(cfg, report)
    check_security_profiles(cfg, report)
    check_ha_backup(cfg, report)
    check_local_in_and_services(cfg, report)
    check_601f_specific(cfg, report)
    return report


# ---------------------------------------------------------------------------
# API FortiOS (optionnel)
# ---------------------------------------------------------------------------

def fetch_config_via_api(base_url: str, token: str, vdom: str = "root", insecure: bool = False) -> str:
    """
    Tente de récupérer une config via REST API FortiOS.
    Nécessite un api-user avec droits lecture.
    """
    url = base_url.rstrip("/") + "/api/v2/monitor/system/config/backup?scope=global"
    # Note: endpoints varient selon version FortiOS ; fallback documentation
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
        method="GET",
    )
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=60) as resp:
            data = resp.read()
            # Peut être binaire conf ou JSON
            try:
                j = json.loads(data.decode("utf-8", errors="replace"))
                if isinstance(j, dict) and "results" in j:
                    return str(j["results"])
                return json.dumps(j, indent=2)
            except json.JSONDecodeError:
                return data.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        raise SystemExit(
            f"Erreur API HTTP {e.code}: {e.reason}. "
            "Préférez un export CLI: `show full-configuration` / backup config."
        ) from e
    except Exception as e:
        raise SystemExit(f"Échec API: {e}. Utilisez un fichier -c config.conf") from e


# ---------------------------------------------------------------------------
# Sorties
# ---------------------------------------------------------------------------

def print_console(report: AuditReport) -> None:
    print("=" * 78)
    print(" AUDIT FORTIGATE 601F — RAPPORT")
    print("=" * 78)
    print(f" Date       : {report.date_audit}")
    print(f" Hostname   : {report.hostname}")
    print(f" Modèle     : {report.modele}")
    print(f" Version    : {report.version}")
    print(f" Serial     : {report.serial}")
    print(f" VDOM       : {report.vdom_mode}")
    print("-" * 78)
    summary = report.summary()
    fails = [f for f in report.findings if f.statut == "FAIL"]
    fails.sort(key=lambda x: SEVERITY_ORDER.get(x.severite, 9))
    print(
        f" Findings   : {len(report.findings)} total | "
        f"FAIL={summary.get('STATUT_FAIL', 0)} "
        f"WARN={summary.get('STATUT_WARN', 0)} "
        f"PASS={summary.get('STATUT_PASS', 0)} "
        f"INFO={summary.get('STATUT_INFO', 0)}"
    )
    print(
        f" Sévérité FAIL → CRITIQUE={summary.get('CRITIQUE', 0)} "
        f"ELEVE={summary.get('ELEVE', 0)} "
        f"MOYEN={summary.get('MOYEN', 0)} "
        f"FAIBLE={summary.get('FAIBLE', 0)}"
    )
    print("=" * 78)

    for f in sorted(
        report.findings,
        key=lambda x: (0 if x.statut == "FAIL" else 1 if x.statut == "WARN" else 2, SEVERITY_ORDER.get(x.severite, 9)),
    ):
        flag = {"FAIL": "✗", "PASS": "✓", "WARN": "!", "INFO": "i"}.get(f.statut, "?")
        print(f"\n[{flag}] {f.id} | {f.severite} | {f.statut} | {f.categorie}")
        print(f"    {f.titre}")
        print(f"    Détail : {f.detail}")
        if f.statut in ("FAIL", "WARN"):
            print(f"    Remed  : {f.recommandation}")


def export_json(report: AuditReport, path: Path) -> None:
    data = {
        "hostname": report.hostname,
        "modele": report.modele,
        "version": report.version,
        "serial": report.serial,
        "vdom_mode": report.vdom_mode,
        "date_audit": report.date_audit,
        "meta": report.meta,
        "summary": report.summary(),
        "findings": [f.to_dict() for f in report.findings],
    }
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def export_csv(report: AuditReport, path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=["id", "categorie", "severite", "statut", "titre", "detail", "recommandation", "preuve"],
        )
        w.writeheader()
        for f in report.findings:
            w.writerow(f.to_dict())


def export_html(report: AuditReport, path: Path) -> None:
    colors = {
        "CRITIQUE": "#8B0000",
        "ELEVE": "#D9534F",
        "MOYEN": "#F0AD4E",
        "FAIBLE": "#5BC0DE",
        "INFO": "#777",
    }
    rows = []
    for f in report.findings:
        rows.append(
            "<tr>"
            f"<td>{f.id}</td>"
            f"<td>{f.categorie}</td>"
            f"<td style='color:{colors.get(f.severite, '#000')};font-weight:bold'>{f.severite}</td>"
            f"<td>{f.statut}</td>"
            f"<td>{f.titre}</td>"
            f"<td>{f.detail}</td>"
            f"<td>{f.recommandation}</td>"
            "</tr>"
        )
    html = f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<title>Audit FortiGate 601F — {report.hostname}</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;margin:24px;background:#f7f9fc;color:#222}}
h1{{color:#1F4E78}}
.meta td{{padding:4px 12px}}
table{{border-collapse:collapse;width:100%;background:#fff}}
th,td{{border:1px solid #ccc;padding:8px;font-size:13px;vertical-align:top}}
th{{background:#1F4E78;color:#fff}}
tr:nth-child(even){{background:#f2f6fb}}
</style></head><body>
<h1>Audit FortiGate 601F</h1>
<table class="meta">
<tr><td><b>Hostname</b></td><td>{report.hostname}</td>
<td><b>Modèle</b></td><td>{report.modele}</td></tr>
<tr><td><b>Version</b></td><td>{report.version}</td>
<td><b>Date</b></td><td>{report.date_audit}</td></tr>
</table>
<p>Summary: {report.summary()}</p>
<table>
<thead><tr><th>ID</th><th>Catégorie</th><th>Sévérité</th><th>Statut</th><th>Titre</th><th>Détail</th><th>Recommandation</th></tr></thead>
<tbody>
{''.join(rows)}
</tbody></table>
</body></html>"""
    path.write_text(html, encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Audit de configuration FortiGate 601F (fichier conf ou API).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  python3 fg601f_audit.py -c fortigate.conf
  python3 fg601f_audit.py -c fortigate.conf --format csv -o audit.csv
  python3 fg601f_audit.py -c fortigate.conf --format html -o audit.html
  python3 fg601f_audit.py --api https://10.0.0.1 --token TOKEN --insecure
        """,
    )
    p.add_argument("-c", "--config", help="Fichier de configuration FortiGate (CLI export)")
    p.add_argument("--api", help="URL de base FortiGate (https://ip)")
    p.add_argument("--token", help="API token FortiOS")
    p.add_argument("--vdom", default="root", help="VDOM (défaut: root)")
    p.add_argument("--insecure", action="store_true", help="Ignore la vérif certificat TLS (lab uniquement)")
    p.add_argument(
        "--format",
        choices=["console", "json", "csv", "html", "all"],
        default="console",
        help="Format de sortie",
    )
    p.add_argument("-o", "--output", help="Fichier de sortie (json/csv/html)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.config and not (args.api and args.token):
        build_parser().print_help()
        print("\nErreur: fournir -c CONFIG ou --api + --token", file=sys.stderr)
        return 2

    if args.config:
        conf_text = Path(args.config).read_text(encoding="utf-8", errors="replace")
    else:
        conf_text = fetch_config_via_api(args.api, args.token, args.vdom, args.insecure)

    cfg = FortiConfig(conf_text)
    report = run_all_checks(cfg)

    fmt = args.format
    if fmt == "console" or fmt == "all":
        print_console(report)

    out = Path(args.output) if args.output else None
    if fmt == "json" or (fmt == "all" and out):
        target = out or Path("audit_fg601f.json")
        if fmt == "all" and out:
            target = out.with_suffix(".json")
        export_json(report, target)
        print(f"[+] JSON → {target}")

    if fmt == "csv" or (fmt == "all" and out):
        target = out or Path("audit_fg601f.csv")
        if fmt == "all" and out:
            target = out.with_suffix(".csv")
        export_csv(report, target)
        print(f"[+] CSV  → {target}")

    if fmt == "html" or (fmt == "all" and out):
        target = out or Path("audit_fg601f.html")
        if fmt == "all" and out:
            target = out.with_suffix(".html")
        export_html(report, target)
        print(f"[+] HTML → {target}")

    # Code retour: 0 si aucun FAIL critique/élevé, 1 sinon
    hard_fails = [
        f for f in report.findings if f.statut == "FAIL" and f.severite in ("CRITIQUE", "ELEVE")
    ]
    return 1 if hard_fails else 0


if __name__ == "__main__":
    sys.exit(main())
