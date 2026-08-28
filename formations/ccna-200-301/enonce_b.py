# -*- coding: utf-8 -*-
"""Énoncé B — Examen blanc CCNA 200-301 — Niger Certify (propriétaire)."""

EXAM_B = {
    "version": "B",
    "code": "NC-CCNA-BLANC-B-2026",
    "title": "Examen blanc CCNA 200-301",
    "subtitle": "Implementing and Administering Cisco Solutions  ·  v1.1",
    "duration": "120 minutes",
    "n_questions": 50,
    "bareme": "58 points (A 36 + B 16 + C 12)",
    "seuil": "80 %  ≈  47 / 58",
    "referentiel": "Cisco CCNA 200-301 v1.1",
    "header_line": "Examen blanc CCNA 200-301  ·  Document propriétaire",
    "blueprint_title": "Répartition (blueprint Cisco 200-301 v1.1)",
    "blueprint_text": (
        "Fondamentaux réseau 20 %  ·  Accès réseau 20 %  ·  Connectivité IP 25 %  ·  "
        "Services IP 10 %  ·  Sécurité 15 %  ·  Automatisation et programmabilité 10 %."
    ),
    "scoring_notes": [
        "Partie A (Q 1–36) : une seule bonne réponse — 1 point.",
        "Partie B (Q 37–44) : plusieurs bonnes réponses — 2 points, tout ou rien.",
        "Partie C (Q 45–50) : scénarios / sorties IOS — 2 points.",
        "Total : 58 points. Seuil indicatif « prêt CCNA » : 80 % (47/58).",
        "Mini-lab papier : hors barème principal (bonus formateur +10 pts max si activé).",
        "Écrire lisiblement. Les ratures illisibles sont nulles.",
    ],
    "pdf_subject": "Examen blanc CCNA 200-301 v1.1 — Niger Certify",
    "pdf_keywords": "CCNA, Cisco, Niger Certify, examen blanc, propriétaire",
    "corrige_code": "NC-CCNA-BLANC-CORRIGE-2026",
    "corrige_subtitle": "Cisco CCNA 200-301 v1.1  ·  CONFIDENTIEL FORMATEUR",
    "interpretation": (
        "≥ 90 % : prêt examen officiel.  80–89 % : blanc réussi, revoir 1–2 domaines.  "
        "70–79 % : lacunes ciblées (souvent masques, OSPF, ACL, STP).  "
        "&lt; 70 % : ne pas planifier la date Cisco."
    ),
    "parts": [
        {
            "title": "Partie A — QCM (une seule bonne réponse)",
            "intro": "Questions 1 à 36. Cochez une seule case. Barème : 1 point par question. Sujet distinct de la version A.",
            "questions": [
                {
                    "n": 1,
                    "points": 1,
                    "stem": "Par défaut, au bout de combien de temps une entrée MAC inactive est-elle retirée de la table CAM Cisco ?",
                    "choices": [
                        ("A", "30 secondes"),
                        ("B", "60 secondes"),
                        ("C", "300 secondes"),
                        ("D", "3600 secondes"),
                    ],
                    "answer": "C",
                    "explain": "Aging MAC par défaut = 300 s.",
                },
                {
                    "n": 2,
                    "points": 1,
                    "stem": "Quel type de fibre est typiquement choisi pour une liaison campus de 10 km en 10 Gigabit ?",
                    "choices": [
                        ("A", "Cuivre UTP cat. 5e"),
                        ("B", "Multimode OM1 uniquement"),
                        ("C", "Monomode (single-mode)"),
                        ("D", "Câble rollover"),
                    ],
                    "answer": "C",
                    "explain": "Le single-mode couvre les longues distances ; le multimode reste du court/moyen campus.",
                },
                {
                    "n": 3,
                    "points": 1,
                    "stem": "Une interface affiche de nombreux <font face='NC-Mono'>input errors</font> et <font face='NC-Mono'>CRC</font>, duplex identique des deux côtés. Cause la plus probable ?",
                    "choices": [
                        ("A", "Native VLAN mismatch uniquement"),
                        ("B", "Problème de câble / connecteur / interférences"),
                        ("C", "OSPF hello timer"),
                        ("D", "PortFast manquant"),
                    ],
                    "answer": "B",
                    "explain": "CRC / input errors = couche 1 (câble, GBIC, EMI).",
                },
                {
                    "n": 4,
                    "points": 1,
                    "stem": "Quelle séquence décrit le three-way handshake TCP ?",
                    "choices": [
                        ("A", "SYN, ACK, FIN"),
                        ("B", "SYN, SYN-ACK, ACK"),
                        ("C", "ACK, SYN, ACK"),
                        ("D", "FIN, ACK, FIN-ACK"),
                    ],
                    "answer": "B",
                    "explain": "Établissement TCP : SYN → SYN-ACK → ACK.",
                },
                {
                    "n": 5,
                    "points": 1,
                    "stem": "Adresse hôte <font face='NC-Mono'>172.16.5.130/26</font>. Quelle est l'adresse de réseau ?",
                    "choices": [
                        ("A", "172.16.5.0"),
                        ("B", "172.16.5.128"),
                        ("C", "172.16.5.192"),
                        ("D", "172.16.5.130"),
                    ],
                    "answer": "B",
                    "explain": "/26 = blocs de 64. 128–191 → réseau .128.",
                },
                {
                    "n": 6,
                    "points": 1,
                    "stem": "Combien d'hôtes utilisables dans un <font face='NC-Mono'>/29</font> IPv4 ?",
                    "choices": [
                        ("A", "4"),
                        ("B", "6"),
                        ("C", "8"),
                        ("D", "14"),
                    ],
                    "answer": "B",
                    "explain": "2^3 − 2 = 6.",
                },
                {
                    "n": 7,
                    "points": 1,
                    "stem": "Un PC affiche l'adresse <font face='NC-Mono'>169.254.23.10/16</font>. Que signifie-t-elle le plus souvent ?",
                    "choices": [
                        ("A", "Adresse privée RFC 1918"),
                        ("B", "APIPA : échec d'obtention DHCP"),
                        ("C", "Adresse de loopback"),
                        ("D", "Adresse multicast"),
                    ],
                    "answer": "B",
                    "explain": "169.254.0.0/16 = link-local IPv4 / APIPA.",
                },
                {
                    "n": 8,
                    "points": 1,
                    "stem": "Quelle adresse IPv6 est une adresse <b>unique local</b> (ULA) ?",
                    "choices": [
                        ("A", "2001:db8::10"),
                        ("B", "fe80::10"),
                        ("C", "fd12:3456:789a::10"),
                        ("D", "ff02::2"),
                    ],
                    "answer": "C",
                    "explain": "ULA = fc00::/7, en pratique fd00::/8.",
                },
                {
                    "n": 9,
                    "points": 1,
                    "stem": "SLAAC avec EUI-64 modifié : le 7e bit de l'identifiant d'interface (bit U/L) est :",
                    "choices": [
                        ("A", "Toujours mis à 0."),
                        ("B", "Inversé par rapport à la MAC."),
                        ("C", "Remplacé par FF."),
                        ("D", "Ignoré sur Ethernet."),
                    ],
                    "answer": "B",
                    "explain": "Modified EUI-64 inverse le bit Universal/Local.",
                },
                {
                    "n": 10,
                    "points": 1,
                    "stem": "Dans un datacenter <b>spine-leaf</b>, chaque leaf :",
                    "choices": [
                        ("A", "Se connecte uniquement aux autres leaf (full mesh L2)."),
                        ("B", "Se connecte à tous les spine, pas aux autres leaf en général."),
                        ("C", "Doit activer Rapid PVST+ vers les spine."),
                        ("D", "Termine uniquement des VPN DMVPN."),
                    ],
                    "answer": "B",
                    "explain": "Topologie CLOS : leaf–spine, east-west via spine, pas de leaf–leaf.",
                },
                {
                    "n": 11,
                    "points": 1,
                    "stem": "PoE 802.3at (PoE+) fournit environ, au PD :",
                    "choices": [
                        ("A", "15,4 W"),
                        ("B", "30 W (classe 4)"),
                        ("C", "90 W"),
                        ("D", "5 W uniquement"),
                    ],
                    "answer": "B",
                    "explain": "802.3af ≈ 15 W ; at (PoE+) ≈ 30 W ; bt jusqu'à 90 W.",
                },
                {
                    "n": 12,
                    "points": 1,
                    "stem": "Le VLAN par défaut d'un commutateur Cisco (untagged natif d'origine) est :",
                    "choices": [
                        ("A", "VLAN 0"),
                        ("B", "VLAN 1"),
                        ("C", "VLAN 100"),
                        ("D", "VLAN 999"),
                    ],
                    "answer": "B",
                    "explain": "Default VLAN = 1. Bonne pratique : ne pas l'utiliser pour la data.",
                },
                {
                    "n": 13,
                    "points": 1,
                    "stem": "Un mismatch de native VLAN entre deux extrémités d'un trunk provoque surtout :",
                    "choices": [
                        ("A", "La négociation OSPF en area 1."),
                        ("B", "Le mélange / la fuite de trafic untagged et des alertes CDP."),
                        ("C", "La désactivation de SSH."),
                        ("D", "Le passage automatique en access VLAN 1."),
                    ],
                    "answer": "B",
                    "explain": "Les untagged d'un côté tombent dans l'autre native VLAN → fuite L2.",
                },
                {
                    "n": 14,
                    "points": 1,
                    "stem": "Pour qu'un EtherChannel se forme, les ports membres doivent notamment avoir :",
                    "choices": [
                        ("A", "Des vitesses et duplex identiques, mêmes VLAN / mode."),
                        ("B", "Des hostnames identiques."),
                        ("C", "OSPF area 0 obligatoirement."),
                        ("D", "Des adresses MAC identiques configurées à la main."),
                    ],
                    "answer": "A",
                    "explain": "Homogénéité L1/L2 : speed, duplex, VLAN, STP cost, etc.",
                },
                {
                    "n": 15,
                    "points": 1,
                    "stem": "Élection du root port Rapid PVST+ : premier critère (après le root bridge) ?",
                    "choices": [
                        ("A", "Le plus grand port ID local"),
                        ("B", "Le plus faible coût de chemin vers le root"),
                        ("C", "La MAC la plus haute du voisin"),
                        ("D", "Le VLAN ID le plus élevé"),
                    ],
                    "answer": "B",
                    "explain": "Lowest path cost, puis BID du voisin, puis port ID.",
                },
                {
                    "n": 16,
                    "points": 1,
                    "stem": "BPDU Guard versus BPDU Filter :",
                    "choices": [
                        ("A", "Guard err-disable à réception d'un BPDU ; Filter arrête l'envoi/traitement des BPDU."),
                        ("B", "Identiques sur IOS-XE."),
                        ("C", "Filter est obligatoire sur les uplinks core."),
                        ("D", "Guard remplace PortFast."),
                    ],
                    "answer": "A",
                    "explain": "Filter peut créer des boucles s'il est mal placé ; Guard protège l'accès.",
                },
                {
                    "n": 17,
                    "points": 1,
                    "stem": "Un AP en mode <b>FlexConnect</b> (par rapport au mode local) permet surtout :",
                    "choices": [
                        ("A", "D'abandonner tout chiffrement Wi-Fi."),
                        ("B", "Un local switching du trafic data au niveau de la succursale si le CAPWAP tombe."),
                        ("C", "De remplacer le WLC par VTP."),
                        ("D", "D'utiliser uniquement WEP."),
                    ],
                    "answer": "B",
                    "explain": "FlexConnect : switching local optionnel / survie WAN.",
                },
                {
                    "n": 18,
                    "points": 1,
                    "stem": "Quelle méthode d'accès à l'IOS est hors bande et ne dépend pas du plan IP de production ?",
                    "choices": [
                        ("A", "SSH via le SVI de mgmt in-band uniquement"),
                        ("B", "HTTP sur le VLAN data"),
                        ("C", "Console (câble rollover / USB) "),
                        ("D", "Telnet depuis Internet"),
                    ],
                    "answer": "C",
                    "explain": "Console = OOB physique.",
                },
                {
                    "n": 19,
                    "points": 1,
                    "stem": "Dans <font face='NC-Mono'>show ip route</font>, le code <b>L</b> désigne :",
                    "choices": [
                        ("A", "Une route EIGRP interne."),
                        ("B", "L'adresse locale de l'interface (host route /32)."),
                        ("C", "Une route BGP locale."),
                        ("D", "Une route flottante."),
                    ],
                    "answer": "B",
                    "explain": "L = local /32 de l'interface (IOS moderne).",
                },
                {
                    "n": 20,
                    "points": 1,
                    "stem": "Un paquet vers 10.1.1.200. Quelles routes candidates, laquelle gagne ?",
                    "code": "O    10.1.0.0/16  [110/20] via 192.0.2.1\nS    10.1.1.0/25  [1/0] via 192.0.2.2\nC    10.1.1.128/25 is directly connected, Gi0/1",
                    "choices": [
                        ("A", "OSPF /16, car AD 110 est « de protocole »"),
                        ("B", "Statique /25 via 192.0.2.2"),
                        ("C", "Connectée 10.1.1.128/25 (longest match pour .200)"),
                        ("D", "Aucune, le paquet est droppé"),
                    ],
                    "answer": "C",
                    "explain": ".200 ∈ 10.1.1.128/25 (.128–.255). Longest match /25 connected.",
                },
                {
                    "n": 21,
                    "points": 1,
                    "stem": "Quelle commande installe une route statique IPv6 par défaut ?",
                    "choices": [
                        ("A", "ipv6 route ::/0 2001:db8:1::1"),
                        ("B", "ip route 0.0.0.0 0.0.0.0 2001:db8:1::1"),
                        ("C", "ipv6 default-gateway 2001:db8:1::1"),
                        ("D", "ipv6 route 0::0/0 GigabitEthernet0/0 64"),
                    ],
                    "answer": "A",
                    "explain": "Default IPv6 = ::/0.",
                },
                {
                    "n": 22,
                    "points": 1,
                    "stem": "OSPF point-à-point versus broadcast : quelle affirmation est vraie ?",
                    "choices": [
                        ("A", "Le P2P élit un DR/BDR."),
                        ("B", "Le broadcast élit DR/BDR ; le P2P n'en élit pas."),
                        ("C", "Les hello P2P sont toujours à 30 s."),
                        ("D", "Le broadcast n'envoie pas de LSA Type 1."),
                    ],
                    "answer": "B",
                    "explain": "DR/BDR seulement sur multi-accès (broadcast/NBMA).",
                },
                {
                    "n": 23,
                    "points": 1,
                    "stem": "Deux voisins OSPF restent bloqués en <b>EXSTART / EXCHANGE</b>. Cause classique ?",
                    "choices": [
                        ("A", "Area identique"),
                        ("B", "MTU d'interface différent"),
                        ("C", "Même priorité 1"),
                        ("D", "Passive-interface sur un loopback"),
                    ],
                    "answer": "B",
                    "explain": "Mismatch MTU → coincé à l'échange DBD.",
                },
                {
                    "n": 24,
                    "points": 1,
                    "stem": "L'effet de <font face='NC-Mono'>passive-interface GigabitEthernet0/1</font> sous OSPF est :",
                    "choices": [
                        ("A", "D'annoncer le réseau mais de ne pas envoyer de Hello sur cette interface."),
                        ("B", "De supprimer le préfixe de la LSDB."),
                        ("C", "De forcer le DR."),
                        ("D", "D'activer BFD uniquement."),
                    ],
                    "answer": "A",
                    "explain": "Passive = réseau origé, pas d'adjacence sur l'interface.",
                },
                {
                    "n": 25,
                    "points": 1,
                    "stem": "HSRP version 1 : la MAC virtuelle a la forme :",
                    "choices": [
                        ("A", "0000.0c07.acXX (XX = groupe)"),
                        ("B", "0000.5e00.01XX"),
                        ("C", "ffff.ffff.ffff"),
                        ("D", "001c.0f00.0001 uniquement"),
                    ],
                    "answer": "A",
                    "explain": "HSRPv1 0000.0c07.acXX. VRRP = 0000.5e00.01XX.",
                },
                {
                    "n": 26,
                    "points": 1,
                    "stem": "Quelle instruction réalise un NAT statique one-to-one ?",
                    "choices": [
                        ("A", "ip nat inside source static 10.1.1.10 203.0.113.10"),
                        ("B", "ip nat inside source list 1 interface g0/0 overload"),
                        ("C", "ip nat pool POOL 203.0.113.10 203.0.113.20 prefix-length 24"),
                        ("D", "ip nat outside"),
                    ],
                    "answer": "A",
                    "explain": "static = bijection. overload = PAT.",
                },
                {
                    "n": 27,
                    "points": 1,
                    "stem": "NTP : un routeur configuré <font face='NC-Mono'>ntp server 10.0.0.1</font> agit comme :",
                    "choices": [
                        ("A", "Serveur de temps stricte autorité (stratum 0)."),
                        ("B", "Client NTP synchronisé sur 10.0.0.1 (et peut ensuite servir d'autres clients)."),
                        ("C", "Serveur DNS."),
                        ("D", "Relais DHCP."),
                    ],
                    "answer": "B",
                    "explain": "ntp server = je m'aligne sur cette source.",
                },
                {
                    "n": 28,
                    "points": 1,
                    "stem": "SNMPv3 apporte surtout par rapport à SNMPv2c :",
                    "choices": [
                        ("A", "Des community strings plus longues uniquement"),
                        ("B", "Authentification et chiffrement (authPriv)"),
                        ("C", "Le remplacement d'OSPF"),
                        ("D", "UDP port 23"),
                    ],
                    "answer": "B",
                    "explain": "v3 : utilisateurs, auth, priv. v2c = community en clair.",
                },
                {
                    "n": 29,
                    "points": 1,
                    "stem": "Le niveau syslog <b>debugging</b> vaut :",
                    "choices": [
                        ("A", "0"),
                        ("B", "4"),
                        ("C", "6"),
                        ("D", "7"),
                    ],
                    "answer": "D",
                    "explain": "0 = emergencies, 7 = debugging.",
                },
                {
                    "n": 30,
                    "points": 1,
                    "stem": "TFTP par rapport à FTP :",
                    "choices": [
                        ("A", "TFTP utilise UDP, sans authentification native, adapté aux IOS / ROMMON."),
                        ("B", "TFTP utilise TCP 21 et des users."),
                        ("C", "FTP ne peut pas transférer un IOS."),
                        ("D", "TFTP chiffre obligatoirement avec TLS."),
                    ],
                    "answer": "A",
                    "explain": "TFTP = UDP 69, simple ; FTP = TCP, login, mode actif/passif.",
                },
                {
                    "n": 31,
                    "points": 1,
                    "stem": "<font face='NC-Mono'>enable secret</font> versus <font face='NC-Mono'>enable password</font> :",
                    "choices": [
                        ("A", "secret est haché (MD5/PBKDF2 selon IOS) ; password est plus faible / clair type 7 si service password-encryption."),
                        ("B", "password est plus sûr."),
                        ("C", "Les deux sont identiques depuis IOS 12."),
                        ("D", "secret désactive la console."),
                    ],
                    "answer": "A",
                    "explain": "Toujours préférer enable secret ; il l'emporte si les deux existent.",
                },
                {
                    "n": 32,
                    "points": 1,
                    "stem": "ACL étendue : quel masque wildcard autorise exactement 192.168.10.0/24 ?",
                    "choices": [
                        ("A", "255.255.255.0"),
                        ("B", "0.0.0.255"),
                        ("C", "0.0.255.255"),
                        ("D", "255.255.255.255"),
                    ],
                    "answer": "B",
                    "explain": "Wildcard = inverse du masque. /24 → 0.0.0.255.",
                },
                {
                    "n": 33,
                    "points": 1,
                    "stem": "Port-security, violation <font face='NC-Mono'>shutdown</font> : le port passe :",
                    "choices": [
                        ("A", "en forwarding STP"),
                        ("B", "en err-disable"),
                        ("C", "en VLAN 1"),
                        ("D", "en trunk"),
                    ],
                    "answer": "B",
                    "explain": "shutdown = err-disable (récupération manuelle ou errdisable recovery).",
                },
                {
                    "n": 34,
                    "points": 1,
                    "stem": "WPA2-Enterprise s'appuie typiquement sur :",
                    "choices": [
                        ("A", "Une clé PSK unique pour tout le site"),
                        ("B", "802.1X / EAP et un serveur RADIUS"),
                        ("C", "WEP + TKIP uniquement"),
                        ("D", "Open Authentication"),
                    ],
                    "answer": "B",
                    "explain": "Enterprise = 802.1X + RADIUS. Personal = PSK.",
                },
                {
                    "n": 35,
                    "points": 1,
                    "stem": "IPsec site-to-site versus VPN d'accès distant :",
                    "choices": [
                        ("A", "Site-to-site relie des réseaux (LAN-LAN) ; remote access relie un utilisateur/client au site."),
                        ("B", "Identiques, seul le tarif Cisco change."),
                        ("C", "Remote access n'utilise jamais TLS/SSL (AnyConnect)."),
                        ("D", "Site-to-site interdit AES."),
                    ],
                    "answer": "A",
                    "explain": "Deux cas d'usage du blueprint sécurité CCNA.",
                },
                {
                    "n": 36,
                    "points": 1,
                    "stem": "En JSON, <font face='NC-Mono'>{ }</font> et <font face='NC-Mono'>[ ]</font> représentent respectivement :",
                    "choices": [
                        ("A", "Un tableau et un objet"),
                        ("B", "Un objet (paires clé/valeur) et un tableau"),
                        ("C", "Un commentaire et une chaîne"),
                        ("D", "Un booléen et un null"),
                    ],
                    "answer": "B",
                    "explain": "object = {} ; array = [].",
                },
            ],
        },
        {
            "title": "Partie B — Plusieurs réponses",
            "intro": "Questions 37 à 44. Toutes les bonnes cases doivent être cochées, aucune mauvaise. Barème : 2 points, tout ou rien.",
            "questions": [
                {
                    "n": 37,
                    "points": 2,
                    "multi": True,
                    "n_correct": 2,
                    "stem": "Sélectionnez <b>deux</b> caractéristiques du cuivre Ethernet UTP par rapport à la fibre.",
                    "choices": [
                        ("A", "Sensible aux interférences électromagnétiques"),
                        ("B", "Portée typique 100 m pour la paire torsadée horizontal"),
                        ("C", "Immunité totale à l'EMI"),
                        ("D", "Portée native de 80 km sans optique"),
                        ("E", "Utilise uniquement le duplex half à 10G"),
                    ],
                    "answer": "A, B",
                    "explain": "UTP : 100 m, sensible EMI. Fibre : distance + immunité EMI.",
                },
                {
                    "n": 38,
                    "points": 2,
                    "multi": True,
                    "n_correct": 2,
                    "stem": "Sélectionnez <b>deux</b> états de port Rapid PVST+ stables (après convergence).",
                    "choices": [
                        ("A", "Forwarding"),
                        ("B", "Discarding / blocking (non désigné, non root)"),
                        ("C", "OSPF FULL"),
                        ("D", "EXSTART"),
                        ("E", "ARP timeout"),
                    ],
                    "answer": "A, B",
                    "explain": "RSTP : discarding, learning, forwarding. Blocking = héritage PVST.",
                },
                {
                    "n": 39,
                    "points": 2,
                    "multi": True,
                    "n_correct": 2,
                    "stem": "Sélectionnez <b>deux</b> encodages de données courants pour les API REST réseau.",
                    "choices": [
                        ("A", "JSON"),
                        ("B", "XML (selon API)"),
                        ("C", "Spanning-Tree BPDUs"),
                        ("D", "HDLC"),
                        ("E", "CSMA/CD"),
                    ],
                    "answer": "A, B",
                    "explain": "REST : JSON surtout, parfois XML/YANG JSON.",
                },
                {
                    "n": 40,
                    "points": 2,
                    "multi": True,
                    "n_correct": 2,
                    "stem": "Sélectionnez <b>deux</b> familles d'IA citées dans le blueprint CCNA v1.1 pour les opérations réseau.",
                    "choices": [
                        ("A", "IA générative"),
                        ("B", "IA prédictive / machine learning"),
                        ("C", "STP AI root"),
                        ("D", "NAT overlapping AI"),
                        ("E", "Collision IA half-duplex"),
                    ],
                    "answer": "A, B",
                    "explain": "Objectif 6.4 : generative, predictive, ML en NetOps.",
                },
                {
                    "n": 41,
                    "points": 2,
                    "multi": True,
                    "n_correct": 2,
                    "stem": "Sélectionnez <b>deux</b> affirmations correctes sur les API d'un contrôleur SDN.",
                    "choices": [
                        ("A", "Northbound : applications / orchestration vers le contrôleur (souvent REST)."),
                        ("B", "Southbound : contrôleur vers les équipements (NETCONF, APIs, etc.)."),
                        ("C", "Southbound = navigateur de l'utilisateur final."),
                        ("D", "Northbound = CDP uniquement."),
                        ("E", "Les deux remplacent le câblage."),
                    ],
                    "answer": "A, B",
                    "explain": "Northbound vs southbound : applis ↔ contrôleur ↔ fabric.",
                },
                {
                    "n": 42,
                    "points": 2,
                    "multi": True,
                    "n_correct": 2,
                    "stem": "Sélectionnez <b>deux</b> éléments d'un programme de sécurité organisationnel.",
                    "choices": [
                        ("A", "Sensibilisation des utilisateurs"),
                        ("B", "Contrôle d'accès physique"),
                        ("C", "Désactiver tous les mots de passe"),
                        ("D", "Publier les secrets enable sur un wiki public"),
                        ("E", "Remplacer RADIUS par Telnet"),
                    ],
                    "answer": "A, B",
                    "explain": "Blueprint 5.2 : awareness, training, physical access control.",
                },
                {
                    "n": 43,
                    "points": 2,
                    "multi": True,
                    "n_correct": 2,
                    "stem": "Sélectionnez <b>deux</b> faits corrects sur DHCP Snooping.",
                    "choices": [
                        ("A", "Les Offers/Acks depuis un port untrusted sont droppés."),
                        ("B", "Il alimente une table de bindings IP–MAC–VLAN–port."),
                        ("C", "Il remplace totalement IPsec."),
                        ("D", "Il doit être trusted sur tous les ports PC."),
                        ("E", "Il désactive STP."),
                    ],
                    "answer": "A, B",
                    "explain": "Anti-rogue DHCP + base pour DAI / IPSG.",
                },
                {
                    "n": 44,
                    "points": 2,
                    "multi": True,
                    "n_correct": 2,
                    "stem": "Sélectionnez <b>deux</b> affirmations IPv6 correctes.",
                    "choices": [
                        ("A", "Anycast : même préfixe configuré sur plusieurs nœuds, livré au plus proche."),
                        ("B", "Multicast FF02::2 = tous les routeurs du lien."),
                        ("C", "IPv6 conserve le broadcast 255.255.255.255."),
                        ("D", "fe80::/10 est globalement routable sur Internet."),
                        ("E", "Les GUA commencent typiquement par fe80."),
                    ],
                    "answer": "A, B",
                    "explain": "Pas de broadcast IPv6. GUA = 2000::/3. Link-local non routé hors lien.",
                },
            ],
        },
        {
            "title": "Partie C — Scénarios et sorties IOS",
            "intro": "Questions 45 à 50. Lisez la sortie avant de répondre. Barème : 2 points par question.",
            "questions": [
                {
                    "n": 45,
                    "points": 2,
                    "stem": "D'après la table, un paquet vers 8.8.8.8 prend quelle gateway ?",
                    "code": "Gateway of last resort is 203.0.113.1 to network 0.0.0.0\nS*   0.0.0.0/0 [1/0] via 203.0.113.1\nC    203.0.113.0/30 is directly connected, GigabitEthernet0/0\nO    10.0.0.0/8 [110/2] via 10.1.1.2",
                    "choices": [
                        ("A", "10.1.1.2 car OSPF /8 est « plus gros »"),
                        ("B", "203.0.113.1 (default /0, 8.8.8.8 n'est pas dans 10.0.0.0/8)"),
                        ("C", "Aucune : AD 1 interdit Internet"),
                        ("D", "Le paquet est forcément NAT-é vers 10.1.1.2"),
                    ],
                    "answer": "B",
                    "explain": "8.8.8.8 ne matche pas 10/8 ; default-route.",
                },
                {
                    "n": 46,
                    "points": 2,
                    "stem": "Quelle conclusion tirer de cette sortie EtherChannel ?",
                    "code": "SW1# show etherchannel summary\nFlags:  D - down        P - bundled in port-channel\n        I - stand-alone  s - suspended\nNumber of channel-groups in use: 1\nGroup  Port-channel  Protocol    Ports\n------+-------------+-----------+----------------------\n1      Po1(SU)         LACP      Gi1/0/1(P) Gi1/0/2(I)",
                    "choices": [
                        ("A", "Les deux ports sont bundlés (P)."),
                        ("B", "Gi1/0/1 est bundlé ; Gi1/0/2 est stand-alone (échec d'agrégation sur ce membre)."),
                        ("C", "LACP n'est pas en service."),
                        ("D", "Po1 est down (D)."),
                    ],
                    "answer": "B",
                    "explain": "Flag I = independent/stand-alone. Po1(SU) = Layer2 in-use, up.",
                },
                {
                    "n": 47,
                    "points": 2,
                    "stem": "Cette ACL est appliquée inbound sur le LAN. Un PC (10.1.1.50) doit être bloqué vers 203.0.113.10:80 mais peut ping. Que se passe-t-il réellement ?",
                    "code": "access-list 110 permit ip any any\naccess-list 110 deny tcp host 10.1.1.50 host 203.0.113.10 eq 80",
                    "choices": [
                        ("A", "HTTP est bloqué, le ping passe."),
                        ("B", "Tout passe, y compris HTTP : le permit any any est en premier."),
                        ("C", "Tout est bloqué par implicit deny."),
                        ("D", "Seul UDP 80 est bloqué."),
                    ],
                    "answer": "B",
                    "explain": "Les ACL sont top-down ; un permit any en tête court-circuite le deny.",
                },
                {
                    "n": 48,
                    "points": 2,
                    "stem": "PC-A (VLAN 10, SW1 Gi1/0/5 access vlan 10) ping PC-B sur SW2. Trunk OK, mais PC-B est en access vlan 20. Résultat le plus probable ?",
                    "choices": [
                        ("A", "Ping OK : le trunk transporte tous les VLAN."),
                        ("B", "Échec : domaines de broadcast / SVI différents, pas de routage inter-VLAN évoqué."),
                        ("C", "STP bloque forcément Gi1/0/5."),
                        ("D", "ARP IPv6 résout tout."),
                    ],
                    "answer": "B",
                    "explain": "VLAN 10 ≠ 20 = L2 séparés. Sans L3 inter-VLAN, pas de ping.",
                },
                {
                    "n": 49,
                    "points": 2,
                    "stem": "Un contrôleur REST renvoie HTTP 201 après <font face='NC-Mono'>POST /network-device</font> avec un body JSON. Cela signifie surtout :",
                    "choices": [
                        ("A", "Lecture réussie (GET)."),
                        ("B", "Création de ressource réussie."),
                        ("C", "Erreur d'authentification."),
                        ("D", "La ressource a été supprimée."),
                    ],
                    "answer": "B",
                    "explain": "201 Created = POST réussi. 401 = auth. 204/200 DELETE selon API.",
                },
                {
                    "n": 50,
                    "points": 2,
                    "stem": "Réseau traditionnel versus réseau basé sur un contrôleur (Cisco DNA Center / WLC) :",
                    "choices": [
                        ("A", "Le contrôleur centralise la politique et l'automatisation ; les équipements restent le data plane."),
                        ("B", "Le contrôleur remplace tous les câbles."),
                        ("C", "Un WLC interdit CAPWAP."),
                        ("D", "DNA Center n'expose aucune API northbound."),
                    ],
                    "answer": "A",
                    "explain": "Séparation contrôle / données + APIs ; l'underlay physique demeure.",
                },
            ],
        },
    ],
    "minilab": {
        "title": "Mini-lab papier (optionnel formateur — hors barème 58 pts)",
        "intro": (
            "Durée indicative 15 minutes. Sujet distinct de la version A. "
            "Le formateur peut attribuer jusqu'à 10 points bonus."
        ),
        "context_title": "Topologie (description)",
        "topo": (
            "PC-B --- SW-A ===Po1 LACP=== SW-B --- R2 --- FAI\n"
            "VLAN 30 data   VLAN 90 mgmt   native 90\n"
            "R2 : G0/1.30  |  NTP client vers 10.90.0.5\n"
            "SSH v2 seulement sur les VTY  |  ACL 120 bloque Telnet vers R2 depuis le LAN\n"
            "OSPF area 0 sur .30  |  default statique principale AD 1 via FAI"
        ),
        "tasks": [
            "EtherChannel LACP Po1 : deux ports active, trunk allowed 30,90, native 90.",
            "Port PC : access VLAN 30, PortFast, BPDU Guard.",
            "R2 : sous-interface .30 en 10.30.0.1/24, NTP client 10.90.0.5.",
            "Générer RSA, domain niger-certify.ne, VTY transport input ssh, user local.",
            "ACL étendue 120 : deny TCP any vers R2 eq 23, puis permit IP any any, appliquée in sur G0/1.30.",
        ],
        "correction": (
            "interface range Gi1/0/23-24\n"
            " channel-group 1 mode active\n"
            "interface Port-channel1\n"
            " switchport mode trunk\n"
            " switchport trunk native vlan 90\n"
            " switchport trunk allowed vlan 30,90\n"
            "interface Gi1/0/10\n"
            " switchport mode access\n"
            " switchport access vlan 30\n"
            " spanning-tree portfast\n"
            " spanning-tree bpduguard enable\n"
            "hostname R2\n"
            "ip domain-name niger-certify.ne\n"
            "crypto key generate rsa modulus 2048\n"
            "username admin secret <motdepasse>\n"
            "line vty 0 4\n"
            " login local\n"
            " transport input ssh\n"
            "ip ssh version 2\n"
            "interface Gi0/1.30\n"
            " encapsulation dot1Q 30\n"
            " ip address 10.30.0.1 255.255.255.0\n"
            " ip access-group 120 in\n"
            "ntp server 10.90.0.5\n"
            "access-list 120 deny tcp any host 10.30.0.1 eq 23\n"
            "access-list 120 permit ip any any\n"
            "router ospf 1\n"
            " network 10.30.0.0 0.0.0.255 area 0\n"
            "ip route 0.0.0.0 0.0.0.0 <FAI> 1"
        ),
    },
}
