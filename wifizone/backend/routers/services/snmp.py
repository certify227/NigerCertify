"""SNMP monitoring (routeurs MikroTik)."""

import logging
import subprocess

from django.conf import settings

logger = logging.getLogger(__name__)

SNMP_OIDS = {
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "cpuLoad": "1.3.6.1.4.1.2021.11.11.0",
}


def get_snmp_stats(host: str, community: str = "public") -> dict | None:
    """Lit des OID SNMP v2c. Mode mock si MIKROTIK_MOCK_MODE."""
    if settings.MIKROTIK_MOCK_MODE:
        return {
            "sysName": f"MT-{host}",
            "sysUpTime": "3d12h",
            "cpuLoad": "8",
            "source": "mock",
        }

    if not host:
        return None

    stats = {"source": "snmp"}
    for key, oid in SNMP_OIDS.items():
        value = _snmpget(host, community, oid)
        if value:
            stats[key] = value

    return stats if len(stats) > 1 else None


def _snmpget(host: str, community: str, oid: str) -> str | None:
    try:
        result = subprocess.run(
            ["snmpget", "-v2c", "-c", community, host, oid],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            return None
        line = result.stdout.strip()
        if "=" in line:
            return line.split("=", 1)[1].strip().strip('"')
        return line
    except FileNotFoundError:
        logger.warning("snmpget non installé — SNMP désactivé")
        return None
    except Exception as exc:
        logger.warning("SNMP error %s: %s", host, exc)
        return None
