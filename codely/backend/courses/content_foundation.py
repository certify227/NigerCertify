"""
Parcours fondamentaux 1 à 7 — version pédagogique enrichie.
Indices, analogies et explications détaillées sur chaque exercice.
"""

from courses.content_helpers import (
    add_code,
    add_fill,
    add_mc,
    add_tf,
    create_lesson,
    create_track,
    create_unit,
)


def load_python_fondamentaux():
    track = create_track(
        "Python Fondamentaux",
        "python-fondamentaux",
        "Votre premier langage de programmation : on commence doucement, "
        "comme apprendre l'alphabet avant d'écrire des phrases.",
        "🐍",
        "#3776AB",
        1,
    )

    u1 = create_unit(
        track,
        "Étape 1 — Variables & Types",
        "Une variable, c'est une boîte étiquetée qui contient une valeur",
        1,
    )

    l1 = create_lesson(
        u1,
        "Votre première variable",
        "En Python, donner un nom à une valeur, c'est créer une variable — "
        "comme étiqueter une boîte dans un grenier",
        1,
        25,
    )
    add_mc(
        l1,
        "En Python 3, pour stocker le nombre 10 dans une variable x, on écrit :",
        [
            ("var x = 10", False),
            ("x = 10", True),
            ("int x = 10", False),
            ("declare x = 10", False),
        ],
        0,
        hint="Pas de mot-clé comme en Java ou C — juste nom = valeur",
        explanation="Python est simple : x = 10 suffit. Pas besoin de déclarer le type à l'avance.",
    )
    add_mc(
        l1,
        "Le type int en Python représente :",
        [
            ("Un nombre à virgule", False),
            ("Un nombre entier (sans décimales)", True),
            ("Du texte", False),
            ("Une liste", False),
        ],
        1,
        hint="integer = entier en anglais",
        explanation="int = entiers : -3, 0, 42. Pour les décimales, on utilise float.",
    )
    add_tf(
        l1,
        "En Python, « age » et « Age » désignent deux variables différentes.",
        True,
        2,
        hint="Majuscules et minuscules comptent",
        explanation="Python est sensible à la casse : respectez toujours le même nom.",
    )
    add_mc(
        l1,
        "Pour afficher « Bonjour » à l'écran, la fonction standard est :",
        [
            ("echo()", False),
            ("print()", True),
            ("console.log()", False),
            ("display()", False),
        ],
        3,
        hint="Celle qu'on utilise dans presque tous les tutoriels Python",
        explanation="print() envoie du texte vers la console — votre premier outil de débogage !",
    )
    add_tf(
        l1,
        "On peut changer la valeur d'une variable en lui réassignant un nouveau contenu.",
        True,
        4,
        explanation="x = 5 puis x = 10 : la boîte contient maintenant 10. C'est normal et courant.",
    )

    l2 = create_lesson(
        u1,
        "Travailler avec du texte (str)",
        "Les chaînes de caractères permettent de manipuler du texte — "
        "noms, messages, mots de passe affichés…",
        2,
        25,
    )
    add_mc(
        l2,
        "Pour transformer le nombre 42 en texte « 42 », on utilise :",
        [
            ("string()", False),
            ("str()", True),
            ("toString()", False),
            ("text()", False),
        ],
        0,
        hint="Même préfixe que le type str",
        explanation="str(42) donne '42' — utile pour concaténer nombres et texte.",
    )
    add_mc(
        l2,
        "Pour coller deux chaînes « Bon » et « jour », on écrit :",
        [
            ("'Bon' + 'jour'", True),
            ("'Bon'.append('jour')", False),
            ("concat('Bon','jour')", False),
            ("'Bon' & 'jour'", False),
        ],
        1,
        hint="L'opérateur + fonctionne aussi sur le texte",
        explanation="La concaténation avec + assemble les chaînes : 'Bon' + 'jour' → 'Bonjour'.",
    )
    add_fill(
        l2,
        "Pour mettre « hello » en majuscules : s.???()",
        "upper",
        2,
        hint="Tout en CAPITALES",
        explanation="upper() retourne une nouvelle chaîne en majuscules sans modifier l'originale.",
    )
    add_tf(
        l2,
        "Une chaîne Python ne peut pas être modifiée en place — on crée une nouvelle.",
        True,
        3,
        hint="On dit qu'elle est « immuable »",
        explanation="s = 'abc'; s.upper() retourne 'ABC' mais s reste 'abc'. C'est l'immutabilité.",
    )
    add_mc(
        l2,
        "Combien de caractères contient la chaîne 'Python' ?",
        [
            ("5", False),
            ("6", True),
            ("7", False),
            ("Impossible à savoir", False),
        ],
        4,
        hint="Comptez P-y-t-h-o-n",
        explanation="len('Python') retourne 6. len() marche sur les chaînes et les listes.",
    )

    l3 = create_lesson(
        u1,
        "Nombres et calculs",
        "Addition, division, modulo — les calculatrices du programmeur",
        3,
        30,
    )
    add_mc(
        l3,
        "Quel opérateur donne le RESTE de la division de 10 par 3 ?",
        [
            ("/", False),
            ("//", False),
            ("%", True),
            ("**", False),
        ],
        0,
        hint="10 ÷ 3 = 3 reste … ?",
        explanation="10 % 3 = 1 (le reste). Très utile pour tester si un nombre est pair : n % 2 == 0.",
    )
    add_mc(
        l3,
        "2 ** 3 signifie « 2 puissance 3 ». Le résultat est :",
        [
            ("6", False),
            ("8", True),
            ("9", False),
            ("5", False),
        ],
        1,
        hint="2 × 2 × 2",
        explanation="** est l'exposant : 2**3 = 2×2×2 = 8.",
    )
    add_tf(
        l3,
        "En Python 3, 10 / 4 donne 2.5 (un float), pas 2.",
        True,
        2,
        hint="La division / n'est plus entière en Python 3",
        explanation="Utilisez // pour la division entière : 10 // 4 = 2.",
    )
    add_code(
        l3,
        "Affichez le double de 21 (uniquement le nombre)",
        "print(21 * 2)",
        "42",
        3,
        hint="Multipliez 21 par 2 avec *",
        explanation="21 * 2 = 42. Vous venez d'écrire votre premier mini-calcul !",
    )
    add_mc(
        l3,
        "Quelle fonction convertit du texte '3.14' en nombre décimal ?",
        [
            ("int()", False),
            ("float()", True),
            ("str()", False),
            ("number()", False),
        ],
        4,
        hint="Pour les nombres à virgule",
        explanation="float('3.14') → 3.14. int('42') → 42 pour les entiers.",
    )

    u2 = create_unit(
        track,
        "Étape 2 — Conditions & Boucles",
        "Faire des choix (if) et répéter des actions (for, while)",
        2,
    )

    l4 = create_lesson(
        u2,
        "Prendre des décisions avec if",
        "Comme un carrefour : si la condition est vraie, on prend ce chemin",
        1,
        30,
    )
    add_mc(
        l4,
        "Quel mot-clé Python teste une condition ?",
        [
            ("when", False),
            ("if", True),
            ("switch", False),
            ("case", False),
        ],
        0,
        hint="Si … alors …",
        explanation="if age >= 18: exécute le bloc seulement si la condition est vraie.",
    )
    add_mc(
        l4,
        "En Python, comment délimite-t-on un bloc de code (if, for…) ?",
        [
            ("Avec des accolades { }", False),
            ("Avec l'indentation (espaces)", True),
            ("Avec begin/end", False),
            ("Avec des parenthèses", False),
        ],
        1,
        hint="4 espaces au début de chaque ligne du bloc",
        explanation="L'indentation n'est pas optionnelle en Python — c'est la structure du code !",
    )
    add_tf(
        l4,
        "elif permet de tester une autre condition si le if précédent était faux.",
        True,
        2,
        hint="else if en un seul mot",
        explanation="if … elif … elif … else : une chaîne de conditions mutuellement exclusives.",
    )
    add_code(
        l4,
        "Affichez 'pair' si 4 % 2 == 0",
        "if 4 % 2 == 0:\n    print('pair')",
        "pair",
        3,
        hint="4 est divisible par 2",
        explanation="4 % 2 vaut 0, donc la condition est vraie et 'pair' s'affiche.",
    )
    add_mc(
        l4,
        "Quel opérateur signifie « différent de » ?",
        [
            ("<>", False),
            ("!=", True),
            ("=/=", False),
            ("!==", False),
        ],
        4,
        hint="Point d'exclamation + égal",
        explanation="!= teste l'inégalité : if x != 0: …",
    )

    l5 = create_lesson(
        u2,
        "Répéter avec for et while",
        "Les boucles évitent de copier-coller le même code 100 fois",
        2,
        30,
    )
    add_mc(
        l5,
        "range(3) produit les nombres :",
        [
            ("1, 2, 3", False),
            ("0, 1, 2", True),
            ("0, 1, 2, 3", False),
            ("3, 2, 1", False),
        ],
        0,
        hint="Ça commence toujours à 0 et s'arrête AVANT la limite",
        explanation="range(3) = 0, 1, 2. range(1, 4) = 1, 2, 3.",
    )
    add_mc(
        l5,
        "Quelle boucle continue TANT QUE une condition est vraie ?",
        [
            ("for", False),
            ("while", True),
            ("loop", False),
            ("repeat", False),
        ],
        1,
        hint="« tant que » en anglais",
        explanation="while compteur < 10: … — attention aux boucles infinies si la condition ne change jamais !",
    )
    add_tf(
        l5,
        "break sort immédiatement de la boucle, même si la condition while est encore vraie.",
        True,
        2,
        explanation="break = « j'ai trouvé, inutile de continuer ». continue saute juste l'itération courante.",
    )
    add_code(
        l5,
        "Affichez 0, 1, 2 chacun sur une ligne",
        "for i in range(3):\n    print(i)",
        "0\n1\n2",
        3,
        hint="for i in range(3):",
        explanation="Chaque tour de boucle, i vaut 0 puis 1 puis 2.",
    )
    add_mc(
        l5,
        "Que fait range(2, 5) ?",
        [
            ("2, 3, 4", True),
            ("2, 3, 4, 5", False),
            ("0, 1, 2, 3, 4", False),
            ("5, 4, 3, 2", False),
        ],
        4,
        hint="De 2 inclus à 5 exclu",
        explanation="range(début, fin) : fin n'est jamais incluse.",
    )

    l6 = create_lesson(
        u2,
        "Atelier : vos premiers programmes",
        "Mettez en pratique variables, conditions et boucles",
        3,
        40,
    )
    add_code(
        l6,
        "Affichez exactement : Bonjour CodeQuest",
        'print("Bonjour CodeQuest")',
        "Bonjour CodeQuest",
        0,
        hint='print("…") avec des guillemets',
        explanation="Félicitations ! C'est un vrai programme Python.",
    )
    add_code(
        l6,
        "Affichez la somme de 7 et 5 (uniquement le nombre)",
        "print(7 + 5)",
        "12",
        1,
        hint="print(7 + 5)",
        explanation="Python calcule d'abord 7+5=12, puis print affiche le résultat.",
    )
    add_code(
        l6,
        "Affichez les nombres 1, 2, 3 un par ligne",
        "for i in range(1, 4):\n    print(i)",
        "1\n2\n3",
        2,
        hint="range(1, 4)",
        explanation="Vous combinez boucle + affichage — compétence essentielle !",
    )
    add_tf(
        l6,
        "Tester son code petit à petit (une ligne à la fois) est une bonne habitude.",
        True,
        3,
        explanation="Décomposez, testez, corrigez — c'est la méthode des bons développeurs.",
    )

    u3 = create_unit(
        track,
        "Étape 3 — Listes & Dictionnaires",
        "Stocker plusieurs valeurs ensemble — comme un carnet ou un annuaire",
        3,
    )

    l7 = create_lesson(
        u3,
        "Les listes — votre premier tableau",
        "Une liste garde plusieurs valeurs dans un ordre précis : [1, 2, 3]",
        1,
        30,
    )
    add_mc(
        l7,
        "Comment créer une liste vide en Python ?",
        [
            ("list{}", False),
            ("[]", True),
            ("()", False),
            ("{}", False),
        ],
        0,
        hint="Crochets, pas accolades",
        explanation="[] = liste. () = tuple. {} = dictionnaire. Trois structures différentes !",
    )
    add_mc(
        l7,
        "Dans la liste L = ['a', 'b', 'c'], quelle expression donne 'a' ?",
        [
            ("L[0]", True),
            ("L[1]", False),
            ("L.first()", False),
            ("L(0)", False),
        ],
        1,
        hint="Le premier index est 0, pas 1",
        explanation="Indexation à partir de 0 : L[0]='a', L[1]='b', L[2]='c'.",
    )
    add_tf(
        l7,
        "ma_liste.append(5) ajoute 5 à la FIN de la liste.",
        True,
        2,
        explanation="append() agrandit la liste. insert(i, x) insère à une position précise.",
    )
    add_code(
        l7,
        "Affichez la longueur de [1, 2, 3] (uniquement le nombre)",
        "print(len([1, 2, 3]))",
        "3",
        3,
        hint="len()",
        explanation="len() compte les éléments — ici 3.",
    )
    add_mc(
        l7,
        "Quel index donne le DERNIER élément de la liste L ?",
        [
            ("L[-1]", True),
            ("L[0]", False),
            ("L[last]", False),
            ("L.end()", False),
        ],
        4,
        hint="Les index négatifs partent de la fin",
        explanation="L[-1] = dernier, L[-2] = avant-dernier. Très pratique !",
    )

    l8 = create_lesson(
        u3,
        "Les dictionnaires — l'annuaire du code",
        "Chaque valeur a une clé unique : {'nom': 'Alice', 'age': 25}",
        2,
        30,
    )
    add_mc(
        l8,
        "Un dictionnaire vide s'écrit :",
        [
            ("[]", False),
            ("{}", True),
            ("dict[]", False),
            ("()", False),
        ],
        0,
        hint="Accolades pour les paires clé:valeur",
        explanation="{'clé': valeur} — les clés sont souvent des chaînes.",
    )
    add_mc(
        l8,
        "Pour lire la valeur associée à la clé 'ville' dans d, on écrit :",
        [
            ("d.ville", False),
            ("d['ville']", True),
            ("d->ville", False),
            ("d(ville)", False),
        ],
        1,
        hint="Crochets avec la clé entre guillemets",
        explanation="d['ville'] ou d.get('ville', 'inconnu') pour une valeur par défaut.",
    )
    add_fill(
        l8,
        "Pour obtenir toutes les clés : d.???()",
        "keys",
        2,
        hint="« clés » en anglais",
        explanation="d.keys(), d.values(), d.items() — trois vues utiles du dictionnaire.",
    )
    add_code(
        l8,
        "Affichez la valeur de 'a' dans {'a': 1, 'b': 2}",
        "d = {'a': 1, 'b': 2}\nprint(d['a'])",
        "1",
        3,
        hint="d['a']",
        explanation="Les dictionnaires sont parfaits pour représenter des objets (utilisateur, produit…).",
    )
    add_tf(
        l8,
        "Un dictionnaire ne peut pas avoir deux fois la même clé.",
        True,
        4,
        explanation="Les clés sont uniques. Une nouvelle assignation écrase l'ancienne valeur.",
    )


def load_reseaux():
    track = create_track(
        "Réseaux & TCP/IP",
        "reseaux-tcpip",
        "Comprenez comment les ordinateurs se parlent sur Internet — "
        "adresses, protocoles et modèle OSI expliqués simplement.",
        "🌐",
        "#1CB0F6",
        2,
    )

    u1 = create_unit(
        track,
        "Étape 1 — Adresses IP",
        "Chaque machine a une « adresse postale » numérique sur le réseau",
        1,
    )

    l1 = create_lesson(
        u1,
        "IPv4 — L'adresse postale de votre PC",
        "192.168.1.10 : quatre nombres de 0 à 255, séparés par des points",
        1,
        30,
    )
    add_mc(
        l1,
        "Une adresse IPv4 est composée de combien d'octets ?",
        [
            ("2", False),
            ("4", True),
            ("6", False),
            ("8", False),
        ],
        0,
        hint="4 × 8 bits = 32 bits au total",
        explanation="Chaque octet va de 0 à 255. Ex : 192.168.1.1 = 4 octets.",
    )
    add_mc(
        l1,
        "Laquelle est une adresse IP PRIVÉE (réseau local maison/bureau) ?",
        [
            ("8.8.8.8", False),
            ("192.168.1.1", True),
            ("1.1.1.1", False),
            ("142.250.80.46", False),
        ],
        1,
        hint="192.168.x.x est le classique de la box Internet",
        explanation="Plages privées : 10.x, 172.16-31.x, 192.168.x — non routées sur Internet.",
    )
    add_fill(
        l1,
        "Le système qui traduit google.com en adresse IP s'appelle le ???",
        "dns",
        2,
        hint="Domain Name System",
        explanation="Sans DNS, il faudrait mémoriser des IP. Le DNS est l'annuaire d'Internet.",
    )
    add_tf(
        l1,
        "127.0.0.1 (localhost) renvoie toujours vers votre propre machine.",
        True,
        3,
        hint="Utile pour tester un serveur web en local",
        explanation="localhost = « moi-même ». Parfait pour développer avant de déployer.",
    )
    add_mc(
        l1,
        "Que fait la commande ping 8.8.8.8 ?",
        [
            ("Teste si l'adresse IP répond sur le réseau", True),
            ("Télécharge un fichier", False),
            ("Change l'adresse IP", False),
            ("Formate le disque", False),
        ],
        4,
        hint="Premier outil de test réseau",
        explanation="ping envoie des paquets ICMP. Pas de réponse = problème de connectivité.",
    )

    l2 = create_lesson(
        u1,
        "Masques et sous-réseaux",
        "Découper un grand réseau en petits quartiers",
        2,
        35,
    )
    add_mc(
        l2,
        "Un réseau /24 (ex: 192.168.1.0/24) offre combien d'adresses utilisables environ ?",
        [
            ("254", True),
            ("256", False),
            ("65536", False),
            ("2", False),
        ],
        0,
        hint="256 adresses total, moins réseau et broadcast",
        explanation="/24 = 256 adresses. On retire l'adresse réseau et broadcast → ~254 hôtes.",
    )
    add_mc(
        l2,
        "Le masque 255.255.255.0 correspond au CIDR :",
        [
            ("/16", False),
            ("/24", True),
            ("/8", False),
            ("/32", False),
        ],
        1,
        hint="Comptez les bits à 1 dans le masque",
        explanation="255.255.255.0 = 24 bits réseau → notation /24.",
    )
    add_tf(
        l2,
        "La notation 192.168.0.0/24 se lit « slash vingt-quatre » ou « CIDR 24 ».",
        True,
        2,
        explanation="Le nombre après / indique combien de bits identifient le réseau.",
    )
    add_mc(
        l2,
        "Quel protocole attribue automatiquement IP, masque et passerelle à un PC ?",
        [
            ("DNS", False),
            ("DHCP", True),
            ("HTTP", False),
            ("FTP", False),
        ],
        3,
        hint="Dynamic Host Configuration Protocol",
        explanation="Sans DHCP, il faudrait configurer chaque machine à la main.",
    )
    add_mc(
        l2,
        "Deux PC sur le même sous-réseau peuvent communiquer :",
        [
            ("Directement, sans passer par un routeur", True),
            ("Uniquement via Internet", False),
            ("Jamais", False),
            ("Seulement le dimanche", False),
        ],
        4,
        hint="Même quartier = même sous-réseau",
        explanation="Même sous-réseau → communication locale (couche 2/3).",
    )

    l3 = create_lesson(
        u1,
        "IPv6 — L'avenir des adresses",
        "128 bits : assez d'adresses pour longtemps",
        3,
        30,
    )
    add_mc(
        l3,
        "Une adresse IPv6 fait combien de bits ?",
        [
            ("32", False),
            ("64", False),
            ("128", True),
            ("256", False),
        ],
        0,
        hint="Le double d'IPv4 (32 bits) × 4",
        explanation="IPv4 = 32 bits (épuisé). IPv6 = 128 bits (quasi infini).",
    )
    add_tf(
        l3,
        "IPv6 a été créé notamment parce qu'on manquait d'adresses IPv4 publiques.",
        True,
        1,
        explanation="L'explosion d'Internet (smartphones, IoT) a accéléré le besoin d'IPv6.",
    )
    add_fill(
        l3,
        "L'enregistrement DNS pour une IPv6 s'appelle ??? (4 lettres A)",
        "aaaa",
        2,
        hint="AAAA — plus long que A (IPv4)",
        explanation="Enregistrement A = IPv4. AAAA = IPv6.",
    )
    add_mc(
        l3,
        "Le NAT permet souvent à plusieurs appareils de partager :",
        [
            ("Une seule adresse IPv4 publique", True),
            ("Des millions d'IPv6", False),
            ("Un seul câble Ethernet", False),
            ("Le même mot de passe Wi-Fi", False),
        ],
        3,
        hint="Votre box fait du NAT",
        explanation="NAT = traduction d'adresses privées vers l'IP publique du FAI.",
    )

    u2 = create_unit(
        track,
        "Étape 2 — Protocoles & OSI",
        "Les « langues » que les machines utilisent pour échanger",
        2,
    )

    l4 = create_lesson(
        u2,
        "TCP vs UDP — Fiabilité ou vitesse ?",
        "Comme envoyer un colis recommandé (TCP) ou une carte postale (UDP)",
        1,
        30,
    )
    add_mc(
        l4,
        "Quel protocole garantit que les paquets arrivent dans l'ordre, sans perte ?",
        [
            ("UDP", False),
            ("TCP", True),
            ("ICMP", False),
            ("ARP", False),
        ],
        0,
        hint="Utilisé pour le web, les emails…",
        explanation="TCP = connexion fiable. Retransmission si un paquet se perd.",
    )
    add_mc(
        l4,
        "UDP est préféré pour le streaming vidéo car :",
        [
            ("Il est plus rapide et tolère quelques pertes", True),
            ("Il chiffre automatiquement", False),
            ("Il utilise moins d'électricité", False),
            ("Il remplace TCP partout", False),
        ],
        1,
        hint="Mieux vaut sauter une image que bloquer toute la vidéo",
        explanation="UDP = léger, sans accusé de réception. Idéal temps réel.",
    )
    add_tf(
        l4,
        "Le port 80 est réservé par convention au protocole HTTP.",
        True,
        2,
        explanation="Ports courants : 80 HTTP, 443 HTTPS, 22 SSH, 53 DNS.",
    )
    add_mc(
        l4,
        "HTTPS utilise le port :",
        [
            ("80", False),
            ("443", True),
            ("8080", False),
            ("22", False),
        ],
        3,
        hint="HTTP sécurisé = port différent",
        explanation="HTTPS = HTTP chiffré par TLS, port 443 par défaut.",
    )
    add_mc(
        l4,
        "Une socket réseau est identifiée par :",
        [
            ("Adresse IP + numéro de port", True),
            ("Uniquement l'adresse MAC", False),
            ("Le nom de domaine seul", False),
            ("La couleur du câble", False),
        ],
        4,
        hint="Ex: 192.168.1.5:8080",
        explanation="IP identifie la machine, le port identifie l'application (web, ssh…).",
    )

    l5 = create_lesson(
        u2,
        "Le modèle OSI — 7 couches expliquées",
        "Une carte pour comprendre « où » se situe un problème réseau",
        2,
        35,
    )
    add_mc(
        l5,
        "Le modèle OSI compte combien de couches ?",
        [
            ("4", False),
            ("5", False),
            ("7", True),
            ("9", False),
        ],
        0,
        hint="De la physique (câble) à l'application (navigateur)",
        explanation="7 couches : Physique, Liaison, Réseau, Transport, Session, Présentation, Application.",
    )
    add_mc(
        l5,
        "Le protocole IP (adressage) se situe à la couche :",
        [
            ("2 — Liaison", False),
            ("3 — Réseau", True),
            ("4 — Transport", False),
            ("7 — Application", False),
        ],
        1,
        hint="IP = Internet Protocol = routage",
        explanation="Couche 3 = adressage logique et routage entre réseaux.",
    )
    add_fill(
        l5,
        "Les adresses MAC appartiennent à la couche 2 (???net)",
        "ether",
        2,
        hint="Protocole LAN le plus courant",
        explanation="Ethernet/Wi-Fi = couche 2. IP = couche 3. TCP = couche 4.",
    )
    add_tf(
        l5,
        "Quand un site web ne charge pas, le problème peut être à n'importe quelle couche OSI.",
        True,
        3,
        explanation="Méthode de diagnostic : tester couche par couche (câble → IP → DNS → HTTP).",
    )
    add_mc(
        l5,
        "HTTP (navigateur web) est un protocole de couche :",
        [
            ("3", False),
            ("4", False),
            ("7 — Application", True),
            ("1 — Physique", False),
        ],
        4,
        hint="Ce que l'utilisateur voit et utilise",
        explanation="Couche 7 = applications : HTTP, SMTP (mail), FTP…",
    )


# Suite — parcours 3 à 7 enrichis (voir fichier content_foundation_part2.py importé ci-dessous)
