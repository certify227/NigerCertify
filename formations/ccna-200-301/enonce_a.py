# -*- coding: utf-8 -*-
"""Énoncé A — Examen blanc CCNA 200-301 — Niger Certify (propriétaire)."""

EXAM_A = {
    "version": "A",
    "code": "NC-CCNA-BLANC-A-2026",
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
            "intro": "Questions 1 à 36. Cochez une seule case. Barème : 1 point par question.",
            "questions": [
                {
                    "n": 1,
                    "points": 1,
                    "stem": "Un commutateur de niveau 2 reçoit une trame unicast dont l'adresse MAC de destination n'est pas dans la table CAM. Que fait-il ?",
                    "choices": [
                        ("A", "Il jette la trame."),
                        ("B", "Il l'envoie uniquement vers le port root STP."),
                        ("C", "Il la flood sur tous les ports du VLAN sauf le port d'entrée."),
                        ("D", "Il la convertit en broadcast de niveau 3."),
                    ],
                    "answer": "C",
                    "explain": "Unknown unicast : inondation dans le VLAN, port source exclu.",
                },
                {
                    "n": 2,
                    "points": 1,
                    "stem": "Quel câble relie deux commutateurs si aucun port n'est Auto-MDIX et que les deux extrémités sont des ports MDI-X ?",
                    "choices": [
                        ("A", "Droit (straight-through)"),
                        ("B", "Croisé (crossover)"),
                        ("C", "Rollover (console)"),
                        ("D", "Coaxial RG-58"),
                    ],
                    "answer": "B",
                    "explain": "MDI-X vers MDI-X exige un crossover (l'auto-MDIX masque souvent le besoin).",
                },
                {
                    "n": 3,
                    "points": 1,
                    "stem": "Sur une FastEthernet, <font face='NC-Mono'>show interface</font> indique <font face='NC-Mono'>duplex half</font> d'un côté et <font face='NC-Mono'>duplex full</font> de l'autre. Quel symptôme est le plus probable ?",
                    "choices": [
                        ("A", "L'interface passe down/down."),
                        ("B", "Des CRC uniquement du côté full-duplex, sans collision."),
                        ("C", "Collisions tardives / runts du côté half-duplex."),
                        ("D", "Spanning-Tree bloque systématiquement le port."),
                    ],
                    "answer": "C",
                    "explain": "Duplex mismatch : le côté half voit des collisions (y compris tardives).",
                },
                {
                    "n": 4,
                    "points": 1,
                    "stem": "Quelle affirmation sur TCP est correcte ?",
                    "choices": [
                        ("A", "TCP et UDP garantissent l'ordre des segments."),
                        ("B", "UDP établit une session avant d'envoyer des données."),
                        ("C", "TCP est orienté connexion et gère retransmission et contrôle de flux."),
                        ("D", "DHCP utilise TCP port 67."),
                    ],
                    "answer": "C",
                    "explain": "TCP = connexion, ACK, fenêtre. DHCP = UDP 67/68.",
                },
                {
                    "n": 5,
                    "points": 1,
                    "stem": "Adresse hôte : <font face='NC-Mono'>192.168.10.68/27</font>. Quel est le broadcast du sous-réseau ?",
                    "choices": [
                        ("A", "192.168.10.63"),
                        ("B", "192.168.10.95"),
                        ("C", "192.168.10.127"),
                        ("D", "192.168.10.255"),
                    ],
                    "answer": "B",
                    "explain": "/27 = blocs de 32. Plage 64–95, broadcast .95.",
                },
                {
                    "n": 6,
                    "points": 1,
                    "stem": "Combien d'hôtes IPv4 utilisables dans un réseau <font face='NC-Mono'>/28</font> ?",
                    "choices": [
                        ("A", "14"),
                        ("B", "16"),
                        ("C", "30"),
                        ("D", "32"),
                    ],
                    "answer": "A",
                    "explain": "2^(32-28) − 2 = 14.",
                },
                {
                    "n": 7,
                    "points": 1,
                    "stem": "Quelles plages sont privées au sens du RFC 1918 ?",
                    "choices": [
                        ("A", "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"),
                        ("B", "10.0.0.0/8, 172.16.0.0/16, 192.168.0.0/24"),
                        ("C", "127.0.0.0/8, 169.254.0.0/16, 192.168.0.0/16"),
                        ("D", "100.64.0.0/10, 172.16.0.0/12, 192.0.2.0/24"),
                    ],
                    "answer": "A",
                    "explain": "172.16.0.0/12 (172.16–172.31), pas /16.",
                },
                {
                    "n": 8,
                    "points": 1,
                    "stem": "Quelle adresse IPv6 est une adresse <b>link-local</b> ?",
                    "choices": [
                        ("A", "2001:db8:1::1"),
                        ("B", "fd00:1:1::1"),
                        ("C", "fe80::1"),
                        ("D", "ff02::1"),
                    ],
                    "answer": "C",
                    "explain": "Link-local = fe80::/10. fd00 = unique local. ff02::1 = multicast.",
                },
                {
                    "n": 9,
                    "points": 1,
                    "stem": "Le préfixe <font face='NC-Mono'>FF02::1</font> désigne :",
                    "choices": [
                        ("A", "Un anycast de passerelle."),
                        ("B", "Tous les nœuds IPv6 du lien (multicast)."),
                        ("C", "Une adresse unique local."),
                        ("D", "L'adresse solicited-node de ::1."),
                    ],
                    "answer": "B",
                    "explain": "All-nodes multicast link-local.",
                },
                {
                    "n": 10,
                    "points": 1,
                    "stem": "Dans un campus <b>three-tier</b>, où place-t-on généralement le routage inter-VLAN « traditionnel » (SVI) ?",
                    "choices": [
                        ("A", "Access uniquement."),
                        ("B", "Core uniquement."),
                        ("C", "Distribution (ou collapsed core en two-tier)."),
                        ("D", "Sur les points d'accès Wi-Fi."),
                    ],
                    "answer": "C",
                    "explain": "L3 de distribution / collapsed core ; le core reste un backbone haute capacité.",
                },
                {
                    "n": 11,
                    "points": 1,
                    "stem": "En 2,4 GHz, quels canaux 20 MHz sont classiquement non chevauchants ?",
                    "choices": [
                        ("A", "1, 2 et 3"),
                        ("B", "1, 6 et 11"),
                        ("C", "1, 5, 9 et 13"),
                        ("D", "36, 40 et 44"),
                    ],
                    "answer": "B",
                    "explain": "Trio standard Cisco / Wi-Fi : 1, 6 et 11.",
                },
                {
                    "n": 12,
                    "points": 1,
                    "stem": "Un VRF sert principalement à :",
                    "choices": [
                        ("A", "Chiffrer les trames 802.1Q."),
                        ("B", "Isoler des tables de routage (virtualisation L3) sur un même équipement."),
                        ("C", "Remplacer EtherChannel."),
                        ("D", "Agréger des bornes Wi-Fi."),
                    ],
                    "answer": "B",
                    "explain": "Virtual Routing and Forwarding = tables IP séparées.",
                },
                {
                    "n": 13,
                    "points": 1,
                    "stem": "VLAN data 20 et VLAN voix 30. Quelle configuration de port d'accès est correcte ?",
                    "code": "A. switchport mode access\n   switchport access vlan 20\n   switchport voice vlan 30\n\nB. switchport mode trunk\n   switchport trunk allowed vlan 20,30\n\nC. switchport mode access\n   switchport access vlan 20,30\n\nD. switchport mode dynamic auto",
                    "choices": [
                        ("A", "Bloc A"),
                        ("B", "Bloc B"),
                        ("C", "Bloc C"),
                        ("D", "Bloc D"),
                    ],
                    "answer": "A",
                    "explain": "Port d'accès data + voice VLAN (téléphone tague le voice).",
                },
                {
                    "n": 14,
                    "points": 1,
                    "stem": "Sur un trunk 802.1Q, les trames du <b>native VLAN</b> sont :",
                    "choices": [
                        ("A", "Toujours taguées VID 1."),
                        ("B", "Non taguées (untagged)."),
                        ("C", "Encapsulées ISL."),
                        ("D", "Droppées si le VID est différent de 1."),
                    ],
                    "answer": "B",
                    "explain": "Native VLAN = untagged sur 802.1Q.",
                },
                {
                    "n": 15,
                    "points": 1,
                    "stem": "Deux commutateurs doivent former un EtherChannel <b>LACP</b>. Quelle paire de modes fonctionne ?",
                    "choices": [
                        ("A", "on + active"),
                        ("B", "passive + passive"),
                        ("C", "active + active (ou active + passive)"),
                        ("D", "desirable + auto (modes LACP)"),
                    ],
                    "answer": "C",
                    "explain": "LACP = active/active ou active/passive. desirable/auto = PAgP. on n'est pas LACP.",
                },
                {
                    "n": 16,
                    "points": 1,
                    "stem": "En Rapid PVST+, le pont root est celui qui a :",
                    "choices": [
                        ("A", "L'adresse MAC la plus élevée."),
                        ("B", "Le Bridge ID le plus bas (priorité + MAC)."),
                        ("C", "Le plus grand nombre de VLAN."),
                        ("D", "Le plus grand nombre de ports forwarding."),
                    ],
                    "answer": "B",
                    "explain": "Lowest Bridge ID = root.",
                },
                {
                    "n": 17,
                    "points": 1,
                    "stem": "Sur un port d'accès connecté à un PC, la combinaison recommandée est :",
                    "choices": [
                        ("A", "Loop Guard + Root Guard"),
                        ("B", "PortFast + BPDU Guard"),
                        ("C", "BPDU Filter + UplinkFast"),
                        ("D", "Root Guard + PortFast"),
                    ],
                    "answer": "B",
                    "explain": "PortFast accélère ; BPDU Guard err-disable si un switch est branché.",
                },
                {
                    "n": 18,
                    "points": 1,
                    "stem": "Un AP en mode <b>local</b> (CAPWAP) tunnelise vers le WLC :",
                    "choices": [
                        ("A", "Seulement le plan de contrôle ; la data est toujours en local switching."),
                        ("B", "Le contrôle et, par défaut, le trafic data client (central switching)."),
                        ("C", "Uniquement SNMP."),
                        ("D", "Uniquement RADIUS."),
                    ],
                    "answer": "B",
                    "explain": "Mode local : CAPWAP contrôle + data vers le WLC.",
                },
                {
                    "n": 19,
                    "points": 1,
                    "stem": "Quel protocole de découverte de voisins est un standard IEEE (multi-vendeur) ?",
                    "choices": [
                        ("A", "CDP"),
                        ("B", "LLDP"),
                        ("C", "PAgP"),
                        ("D", "VTP"),
                    ],
                    "answer": "B",
                    "explain": "LLDP = IEEE 802.1AB. CDP est Cisco propriétaire.",
                },
                {
                    "n": 20,
                    "points": 1,
                    "stem": "D'après la table de routage ci-dessous, un paquet vers <font face='NC-Mono'>10.10.10.5</font> est envoyé vers :",
                    "code": "D    10.10.0.0/16 [90/3072] via 192.0.2.1\nO    10.10.10.0/24 [110/20] via 192.0.2.2\nS    10.10.10.5/32 [1/0] via 192.0.2.3",
                    "choices": [
                        ("A", "192.0.2.1 (EIGRP, AD plus bas que OSPF)"),
                        ("B", "192.0.2.2 (préfixe plus spécifique que /16)"),
                        ("C", "192.0.2.3 (host route /32, plus spécifique)"),
                        ("D", "La gateway of last resort"),
                    ],
                    "answer": "C",
                    "explain": "Longest prefix match : /32 gagne, avant même l'AD.",
                },
                {
                    "n": 21,
                    "points": 1,
                    "stem": "Un routeur a les deux routes suivantes vers le même préfixe. Quelle route est installée dans la RIB ?",
                    "code": "O  192.168.1.0/24 [110/20] via 10.0.0.1\nR  192.168.1.0/24 [120/1] via 10.0.0.2",
                    "choices": [
                        ("A", "RIP, car la métrique est plus petite."),
                        ("B", "OSPF, car l'Administrative Distance 110 est inférieure à 120."),
                        ("C", "Les deux (ECMP)."),
                        ("D", "Aucune : conflit, table invalide."),
                    ],
                    "answer": "B",
                    "explain": "À préfixe égal, l'AD départage : OSPF 110 vs RIP 120.",
                },
                {
                    "n": 22,
                    "points": 1,
                    "stem": "Route flottante de secours vers 0.0.0.0/0. La route principale est OSPF (AD 110). Quelle commande est correcte ?",
                    "choices": [
                        ("A", "ip route 0.0.0.0 0.0.0.0 203.0.113.1"),
                        ("B", "ip route 0.0.0.0 0.0.0.0 203.0.113.1 90"),
                        ("C", "ip route 0.0.0.0 0.0.0.0 203.0.113.1 210"),
                        ("D", "ip route 0.0.0.0 0.0.0.0 203.0.113.1 1"),
                    ],
                    "answer": "C",
                    "explain": "Floating static : AD supérieure à 110 (210 est classique).",
                },
                {
                    "n": 23,
                    "points": 1,
                    "stem": "En OSPFv2 multi-accès broadcast, le DR est élu selon :",
                    "choices": [
                        ("A", "La plus petite IPv4 d'interface."),
                        ("B", "La priorité OSPF la plus haute, puis le Router-ID le plus haut."),
                        ("C", "Uniquement le premier routeur allumé."),
                        ("D", "L'Administrative Distance la plus basse."),
                    ],
                    "answer": "B",
                    "explain": "Priority (0 = inéligible) puis RID le plus élevé.",
                },
                {
                    "n": 24,
                    "points": 1,
                    "stem": "Deux routeurs OSPF restent en état <b>2-WAY</b> sur un Ethernet à plusieurs routeurs. Quelle explication est <b>normale</b> ?",
                    "choices": [
                        ("A", "Hello timer mismatch."),
                        ("B", "Ce sont des DROTHER : le 2-WAY entre DROTHER est attendu."),
                        ("C", "MTU mismatch."),
                        ("D", "Area mismatch."),
                    ],
                    "answer": "B",
                    "explain": "Seuls DR/BDR forment FULL avec tout le monde ; DROTHER–DROTHER = 2-WAY.",
                },
                {
                    "n": 25,
                    "points": 1,
                    "stem": "Le Router-ID OSPF, si rien n'est configuré manuellement, est :",
                    "choices": [
                        ("A", "Toujours 0.0.0.0."),
                        ("B", "La plus haute IPv4 de Loopback, sinon la plus haute IPv4 d'interface up."),
                        ("C", "L'IPv6 link-local."),
                        ("D", "Toujours l'IP de GigabitEthernet0/0."),
                    ],
                    "answer": "B",
                    "explain": "Règle IOS classique du RID IPv4.",
                },
                {
                    "n": 26,
                    "points": 1,
                    "stem": "Rôle principal d'un FHRP (HSRP / VRRP / GLBP) :",
                    "choices": [
                        ("A", "Équilibrer les VLAN d'accès."),
                        ("B", "Fournir une IP de passerelle virtuelle redondante aux hôtes."),
                        ("C", "Remplacer OSPF."),
                        ("D", "Assurer le NAT dynamique."),
                    ],
                    "answer": "B",
                    "explain": "VIP de default-gateway pour les PC.",
                },
                {
                    "n": 27,
                    "points": 1,
                    "stem": "NAT overload (PAT) : quelle commande associe une ACL à un pool avec translation de ports ?",
                    "choices": [
                        ("A", "ip nat inside source static 10.0.0.1 203.0.113.5"),
                        ("B", "ip nat inside source list 1 pool POOL overload"),
                        ("C", "ip nat outside source list 1 interface g0/0"),
                        ("D", "ip nat pool POOL 10.0.0.1 10.0.0.10"),
                    ],
                    "answer": "B",
                    "explain": "PAT = list + pool (ou interface) + mot-clé overload.",
                },
                {
                    "n": 28,
                    "points": 1,
                    "stem": "Un PC n'obtient pas d'adresse IP. Le serveur DHCP est sur un autre subnet. Que manque-t-il le plus souvent <b>sur le SVI / l'interface du VLAN client</b> ?",
                    "choices": [
                        ("A", "ip dhcp excluded-address"),
                        ("B", "ip helper-address &lt;IP-serveur-DHCP&gt;"),
                        ("C", "ip dhcp snooping trust uniquement"),
                        ("D", "NAT PAT"),
                    ],
                    "answer": "B",
                    "explain": "DHCP relay = helper-address (UDP 67).",
                },
                {
                    "n": 29,
                    "points": 1,
                    "stem": "Le niveau syslog <b>notifications</b> correspond à :",
                    "choices": [
                        ("A", "0"),
                        ("B", "3"),
                        ("C", "5"),
                        ("D", "7"),
                    ],
                    "answer": "C",
                    "explain": "0 emergencies … 5 notifications … 7 debugging.",
                },
                {
                    "n": 30,
                    "points": 1,
                    "stem": "En QoS, quelle distinction est correcte entre <b>policing</b> et <b>shaping</b> ?",
                    "choices": [
                        ("A", "Les deux bufferisent toujours l'excès."),
                        ("B", "Le policing droppe ou re-marque ; le shaping bufferise et lisse."),
                        ("C", "Le shaping droppe ; le policing bufferise."),
                        ("D", "Identiques : simple vocabulaire Cisco différent."),
                    ],
                    "answer": "B",
                    "explain": "Police = drop/remark ; shape = file d'attente / lissage.",
                },
                {
                    "n": 31,
                    "points": 1,
                    "stem": "Pour activer SSH v2 sur IOS, l'ordre minimal correct est : 1) hostname + ip domain-name  2) crypto key generate rsa  3) ligne vty : transport input ssh + login local.",
                    "choices": [
                        ("A", "3 puis 1 puis 2"),
                        ("B", "1 puis 2 puis 3"),
                        ("C", "2 uniquement"),
                        ("D", "Telnet doit rester activé en parallèle"),
                    ],
                    "answer": "B",
                    "explain": "Le nom de domaine est requis pour générer la paire RSA, puis on restreint les VTY.",
                },
                {
                    "n": 32,
                    "points": 1,
                    "stem": "Port-security : <font face='NC-Mono'>mac-address sticky</font> et violation <font face='NC-Mono'>restrict</font>. Face à une MAC inconnue :",
                    "choices": [
                        ("A", "Le port passe err-disable."),
                        ("B", "La trame est droppée, un compteur / log augmente, le port reste up."),
                        ("C", "Le VLAN est suspendu."),
                        ("D", "DAI coupe l'ARP."),
                    ],
                    "answer": "B",
                    "explain": "restrict ≠ shutdown (err-disable).",
                },
                {
                    "n": 33,
                    "points": 1,
                    "stem": "DHCP Snooping : quels ports doivent être <b>trusted</b> ?",
                    "choices": [
                        ("A", "Tous les ports d'accès PC."),
                        ("B", "Les uplinks vers le DHCP légitime / l'infrastructure."),
                        ("C", "Les ports voix uniquement."),
                        ("D", "Aucun : tout untrusted suffit toujours."),
                    ],
                    "answer": "B",
                    "explain": "Trust = chemin du serveur DHCP officiel.",
                },
                {
                    "n": 34,
                    "points": 1,
                    "stem": "Dynamic ARP Inspection s'appuie principalement sur :",
                    "choices": [
                        ("A", "La table CAM uniquement."),
                        ("B", "La base DHCP Snooping (bindings IP–MAC)."),
                        ("C", "La LSDB OSPF."),
                        ("D", "802.1X uniquement."),
                    ],
                    "answer": "B",
                    "explain": "DAI compare l'ARP à la base snooping (ou ARP ACLs).",
                },
                {
                    "n": 35,
                    "points": 1,
                    "stem": "WPA3-Personal utilise principalement :",
                    "choices": [
                        ("A", "TKIP + PSK"),
                        ("B", "SAE (Dragonfly) à la place du 4-way handshake PSK de WPA2"),
                        ("C", "WEP 128"),
                        ("D", "Open + filtrage MAC"),
                    ],
                    "answer": "B",
                    "explain": "WPA3-Personal = SAE.",
                },
                {
                    "n": 36,
                    "points": 1,
                    "stem": "Dans une API REST, <font face='NC-Mono'>PUT /interfaces/Gi0/0</font> avec un body JSON complet correspond à l'opération CRUD :",
                    "choices": [
                        ("A", "Create"),
                        ("B", "Read"),
                        ("C", "Update (remplacement)"),
                        ("D", "Delete"),
                    ],
                    "answer": "C",
                    "explain": "PUT = remplacement / mise à jour. POST = create. GET = read.",
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
                    "stem": "Sélectionnez <b>deux</b> caractéristiques d'UDP.",
                    "choices": [
                        ("A", "Contrôle de congestion intégré"),
                        ("B", "En-tête plus léger que TCP"),
                        ("C", "Pas d'établissement de session"),
                        ("D", "Numéros de séquence obligatoires pour réordonner"),
                        ("E", "Three-way handshake"),
                    ],
                    "answer": "B, C",
                    "explain": "UDP = connectionless, en-tête 8 octets.",
                },
                {
                    "n": 38,
                    "points": 2,
                    "multi": True,
                    "n_correct": 2,
                    "stem": "Sélectionnez <b>deux</b> conditions pour qu'une adjacence OSPF s'établisse.",
                    "choices": [
                        ("A", "Même Router-ID"),
                        ("B", "Même Area ID"),
                        ("C", "Hello / Dead timers identiques"),
                        ("D", "Même Administrative Distance"),
                        ("E", "Même hostname"),
                    ],
                    "answer": "B, C",
                    "explain": "Area + timers (aussi MTU, auth, flags stub, type de réseau). RID identique casse l'adjacence.",
                },
                {
                    "n": 39,
                    "points": 2,
                    "multi": True,
                    "n_correct": 2,
                    "stem": "Sélectionnez <b>deux</b> éléments d'une architecture SDN / fabric.",
                    "choices": [
                        ("A", "Overlay (tunnels VXLAN, etc.)"),
                        ("B", "Underlay (routage IP sous-jacent)"),
                        ("C", "Spanning-Tree comme unique plan de contrôle obligatoire"),
                        ("D", "Telnet comme northbound API"),
                        ("E", "Un seul collision domain"),
                    ],
                    "answer": "A, B",
                    "explain": "Fabric = underlay IP + overlay (souvent VXLAN) + contrôleur.",
                },
                {
                    "n": 40,
                    "points": 2,
                    "multi": True,
                    "n_correct": 2,
                    "stem": "Sélectionnez <b>deux</b> verbes HTTP REST et leur usage habituel.",
                    "choices": [
                        ("A", "GET = lecture (Read)"),
                        ("B", "POST = création (Create)"),
                        ("C", "DELETE = lecture"),
                        ("D", "PATCH = suppression"),
                        ("E", "OPTIONS = remplacement complet de la ressource"),
                    ],
                    "answer": "A, B",
                    "explain": "CRUD : GET/POST/PUT-PATCH/DELETE.",
                },
                {
                    "n": 41,
                    "points": 2,
                    "multi": True,
                    "n_correct": 2,
                    "stem": "Sélectionnez <b>deux</b> affirmations correctes sur Ansible et Terraform.",
                    "choices": [
                        ("A", "Ansible est souvent agentless (SSH / API)."),
                        ("B", "Terraform est orienté infrastructure as code et fichier d'état (provisioning)."),
                        ("C", "Ansible exige un agent sur chaque switch IOS-XE."),
                        ("D", "Terraform remplace OSPF."),
                        ("E", "Les deux sont des protocoles de niveau 2."),
                    ],
                    "answer": "A, B",
                    "explain": "Ansible agentless ; Terraform = IaC déclaratif avec state.",
                },
                {
                    "n": 42,
                    "points": 2,
                    "multi": True,
                    "n_correct": 2,
                    "stem": "Sélectionnez <b>deux</b> méthodes d'accès <b>chiffrées</b> à un équipement.",
                    "choices": [
                        ("A", "Telnet"),
                        ("B", "SSH"),
                        ("C", "HTTP"),
                        ("D", "HTTPS"),
                        ("E", "SNMP v1 community"),
                    ],
                    "answer": "B, D",
                    "explain": "SSH et HTTPS chiffrent. Telnet/HTTP/SNMPv1 non.",
                },
                {
                    "n": 43,
                    "points": 2,
                    "multi": True,
                    "n_correct": 2,
                    "stem": "Sélectionnez <b>deux</b> rôles AAA.",
                    "choices": [
                        ("A", "Authentication : qui es-tu ?"),
                        ("B", "Authorization : que as-tu le droit de faire ?"),
                        ("C", "Accounting : chiffrement des paquets utilisateur"),
                        ("D", "Authentication : liste de contrôle d'accès IP"),
                        ("E", "Authorization : niveau de sévérité syslog"),
                    ],
                    "answer": "A, B",
                    "explain": "Accounting = journalisation d'activité, pas le chiffrement.",
                },
                {
                    "n": 44,
                    "points": 2,
                    "multi": True,
                    "n_correct": 2,
                    "stem": "Sélectionnez <b>deux</b> types d'adresses IPv6 <b>unicast</b>.",
                    "choices": [
                        ("A", "Global unicast"),
                        ("B", "Unique local"),
                        ("C", "Solicited-node (multicast)"),
                        ("D", "FF02::2"),
                        ("E", "Broadcast IPv6"),
                    ],
                    "answer": "A, B",
                    "explain": "GUA + ULA (+ link-local). Pas de broadcast IPv6. Solicited-node = multicast.",
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
                    "stem": "Quelle affirmation est vraie d'après la sortie suivante ?",
                    "code": "SW1# show spanning-tree vlan 10\nVLAN0010\n  Root ID    Priority    24586\n             Address     0062.ec9d.aa80\n             This bridge is the root\nInterface        Role Sts Cost      Prio.Nbr Type\nGi1/0/1          Desg FWD 4         128.1    P2p\nGi1/0/2          Desg FWD 4         128.2    P2p Edge",
                    "choices": [
                        ("A", "SW1 n'est pas root."),
                        ("B", "SW1 est root ; Gi1/0/2 est un port edge (PortFast) forwarding."),
                        ("C", "Gi1/0/1 est un root port."),
                        ("D", "Le VLAN 10 est filtré sur les trunks."),
                    ],
                    "answer": "B",
                    "explain": "« This bridge is the root » + type Edge = PortFast.",
                },
                {
                    "n": 46,
                    "points": 2,
                    "stem": "Hôte 10.1.1.50/24, passerelle 10.1.1.1. Le ping vers 8.8.8.8 renvoie « destination unreachable » depuis 10.1.1.1. La route par défaut existe, Gi0/0 WAN est up/up. Cause la plus probable ?",
                    "code": "C    10.1.1.0/24 is directly connected, Vlan10\nS*   0.0.0.0/0 [1/0] via 203.0.113.1",
                    "choices": [
                        ("A", "Pas de route par défaut."),
                        ("B", "NAT (ou ACL) manquant / mal placé sur le trafic sortant."),
                        ("C", "VLAN 10 down."),
                        ("D", "OSPF non configuré — obligatoire pour Internet."),
                    ],
                    "answer": "B",
                    "explain": "Default présente ; l'unreachable depuis la gw évoque l'absence de NAT/PAT (RFC1918).",
                },
                {
                    "n": 47,
                    "points": 2,
                    "stem": "ACL appliquée <b>in</b> sur l'interface LAN G0/1. Un PC du LAN fait un Telnet vers 203.0.113.10. Résultat ?",
                    "code": "access-list 100 deny tcp any host 203.0.113.10 eq 23\naccess-list 100 permit ip any any\ninterface GigabitEthernet0/1\n ip access-group 100 in",
                    "choices": [
                        ("A", "Autorisé : l'ACL est trop tardive."),
                        ("B", "Refusé (deny Telnet) ; le reste du trafic IP est permis ensuite."),
                        ("C", "Tout le trafic LAN est droppé (implicit deny en tête)."),
                        ("D", "Seul SSH est droppé."),
                    ],
                    "answer": "B",
                    "explain": "Première ligne deny TCP/23 ; puis permit ip any any.",
                },
                {
                    "n": 48,
                    "points": 2,
                    "stem": "Dans le JSON ci-dessous, combien d'objets contient le tableau <font face='NC-Mono'>interface</font> ?",
                    "code": '{\n  "ietf-interfaces:interfaces": {\n    "interface": [\n      {"name": "Gi0/0", "enabled": true},\n      {"name": "Gi0/1", "enabled": false}\n    ]\n  }\n}',
                    "choices": [
                        ("A", "1"),
                        ("B", "2"),
                        ("C", "3"),
                        ("D", "JSON invalide (les deux-points sont interdits)"),
                    ],
                    "answer": "B",
                    "explain": "Tableau JSON [ ... ] de deux objets.",
                },
                {
                    "n": 49,
                    "points": 2,
                    "stem": "WLC : WLAN CORP, WPA2-PSK, interface VLAN 40, AP mode local. Le client s'associe mais n'a pas d'IP. Le DHCP est dans le VLAN 40. Cause la plus fréquente côté wireless ?",
                    "choices": [
                        ("A", "Canaux 1+6+11 utilisés en 5 GHz."),
                        ("B", "Dynamic interface / VLAN du WLAN mal mappé, ou relais DHCP absent sur ce VLAN."),
                        ("C", "CDP désactivé sur les switches."),
                        ("D", "Native VLAN = 40 sur tous les trunks d'accès PC."),
                    ],
                    "answer": "B",
                    "explain": "Association ≠ obtention d'IP : mapping WLAN → VLAN + DHCP/relay.",
                },
                {
                    "n": 50,
                    "points": 2,
                    "stem": "Plan de contrôle versus plan de données :",
                    "choices": [
                        ("A", "Le data plane calcule OSPF ; le control plane forwarde les paquets."),
                        ("B", "Le control plane construit les tables (OSPF, ARP, MAC) ; le data plane commute / route les paquets."),
                        ("C", "Une southbound API est un REST vers l'utilisateur (DNA Center)."),
                        ("D", "L'overlay désigne uniquement le câblage cuivre."),
                    ],
                    "answer": "B",
                    "explain": "Control = décision / protocoles ; data = forwarding. Northbound = vers applis/contrôleur.",
                },
            ],
        },
    ],
    "minilab": {
        "title": "Mini-lab papier (optionnel formateur — hors barème 58 pts)",
        "intro": (
            "Durée indicative 15 minutes. Écrivez les commandes IOS essentielles. "
            "Le formateur peut attribuer jusqu'à 10 points bonus."
        ),
        "context_title": "Topologie (description)",
        "topo": (
            "PC-A --- SW1 ===trunk=== SW2 --- R1 --- Internet\n"
            "VLAN 10 (PC)   VLAN 99 (mgmt)   native 99 sur le trunk\n"
            "R1 : sous-interface G0/1.10  |  NAT PAT sur G0/0\n"
            "OSPF area 0 pour les LAN internes uniquement\n"
            "Default-route statique flottante via FAI de secours (AD 210)"
        ),
        "tasks": [
            "Trunk SW1 Gi1/0/24 : 802.1Q, allowed VLAN 10 et 99, native 99.",
            "Port PC : access VLAN 10, PortFast, BPDU Guard, port-security sticky maximum 2.",
            "R1 : sous-interface .10, helper DHCP 10.10.99.10.",
            "PAT : ACL 1 autorisant 10.10.10.0/24, overload sur G0/0.",
            "OSPF process 1, router-id 1.1.1.1, network de G0/1.10 en area 0 ; ne pas originer la default dans OSPF.",
        ],
        "correction": (
            "interface Gi1/0/24\n"
            " switchport mode trunk\n"
            " switchport trunk native vlan 99\n"
            " switchport trunk allowed vlan 10,99\n"
            "interface Gi1/0/1\n"
            " switchport mode access\n"
            " switchport access vlan 10\n"
            " spanning-tree portfast\n"
            " spanning-tree bpduguard enable\n"
            " switchport port-security\n"
            " switchport port-security maximum 2\n"
            " switchport port-security mac-address sticky\n"
            "interface Gi0/1.10\n"
            " encapsulation dot1Q 10\n"
            " ip address 10.10.10.1 255.255.255.0\n"
            " ip helper-address 10.10.99.10\n"
            " ip nat inside\n"
            "interface Gi0/0\n"
            " ip nat outside\n"
            "access-list 1 permit 10.10.10.0 0.0.0.255\n"
            "ip nat inside source list 1 interface GigabitEthernet0/0 overload\n"
            "router ospf 1\n"
            " router-id 1.1.1.1\n"
            " network 10.10.10.0 0.0.0.255 area 0\n"
            "ip route 0.0.0.0 0.0.0.0 <FAI-backup> 210"
        ),
    },
}
