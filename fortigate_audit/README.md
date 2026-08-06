# Audit FortiGate 601F

Script Python d'audit de durcissement pour **FortiGate 601F** (FG6H1F).

## Ce qui est audité

| Catégorie | Exemples de contrôles |
|-----------|------------------------|
| Accès admin | HTTP/Telnet, trusted hosts, MFA, password-policy, timeout, ports |
| SNMP | Community v1/v2c vs SNMPv3 |
| NTP / DNS | Sync temps, résolveurs |
| Logs | Syslog / FortiAnalyzer |
| Politiques | any-any, logtraffic, profils UTM |
| SSL inspection | Profils appliqués aux policies |
| VPN | SSL-VPN, crypto IPsec faible |
| UTM | IPS, AV, AppCtrl, WebFilter |
| HA | Cluster A-P / standalone |
| Spécifique 601F | NP7 / ASIC offload, anti-replay |

## Prérequis

- Python 3.10+
- Fichier de config CLI exporté depuis le FortiGate

### Exporter la configuration

```bash
# CLI FortiGate
execute backup config tftp <fichier.conf> <serveur_tftp>

# Ou depuis la GUI : System → Backup
# Ou : show full-configuration > fg601f.conf
```

## Utilisation

```bash
# Rapport console
python3 fortigate_audit/fg601f_audit.py -c fortigate_audit/samples/fg601f_lab.conf

# JSON
python3 fortigate_audit/fg601f_audit.py -c fg601f.conf --format json -o audit.json

# CSV
python3 fortigate_audit/fg601f_audit.py -c fg601f.conf --format csv -o audit.csv

# HTML
python3 fortigate_audit/fg601f_audit.py -c fg601f.conf --format html -o audit.html

# Tous les formats
python3 fortigate_audit/fg601f_audit.py -c fg601f.conf --format all -o audit_out
```

### API (optionnel / lab)

```bash
python3 fortigate_audit/fg601f_audit.py \
  --api https://IP_FORTIGATE \
  --token <API_TOKEN> \
  --insecure
```

> L'export fichier CLI reste la méthode recommandée (plus fiable et complète).

## Codes retour

| Code | Signification |
|------|----------------|
| 0 | Aucun FAIL CRITIQUE/ELEVE |
| 1 | Au moins un écart CRITIQUE ou ELEVE |
| 2 | Arguments invalides |

## Échantillon

`samples/fg601f_lab.conf` — configuration volontairement non conforme pour démonstration.
