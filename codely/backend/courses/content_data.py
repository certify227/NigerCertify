"""Définition de tout le contenu pédagogique CodeQuest."""

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
        "Variables, conditions, boucles, listes et premiers programmes.",
        "🐍",
        "#3776AB",
        1,
    )

    # --- Unité 1 : Variables & Types ---
    u1 = create_unit(track, "Variables & Types", "Les briques de base du langage", 1)

    l1 = create_lesson(u1, "Introduction aux variables", "Déclarer et utiliser des variables", 1, 25)
    add_mc(l1, "Quel mot-clé utilise-t-on pour déclarer une variable en Python ?", [
        ("var x = 10", False), ("x = 10", True), ("int x = 10", False), ("declare x = 10", False),
    ], 0, hint="Pas de mot-clé spécial en Python 3", explanation="En Python, on assigne directement : x = 10.")
    add_mc(l1, "Quel type représente un nombre entier ?", [
        ("float", False), ("int", True), ("number", False), ("integer", False),
    ], 1, explanation="int est le type des entiers.")
    add_tf(l1, "Les noms de variables sont sensibles à la casse.", True, 2,
           explanation="myVar et myvar sont deux variables différentes.")
    add_mc(l1, "Quelle fonction affiche du texte à l'écran ?", [
        ("echo()", False), ("print()", True), ("console.log()", False), ("display()", False),
    ], 3, explanation="print() est la fonction d'affichage standard en Python.")

    l2 = create_lesson(u1, "Chaînes de caractères", "Manipuler du texte avec str", 2, 25)
    add_mc(l2, "Quelle fonction convertit un nombre en chaîne ?", [
        ("string()", False), ("str()", True), ("toString()", False), ("text()", False),
    ], 0, explanation="str() convertit tout objet en texte.")
    add_mc(l2, "Comment concaténer 'Hello' et 'World' ?", [
        ("'Hello' + 'World'", True), ("'Hello'.append('World')", False),
        ("concat('Hello','World')", False), ("'Hello' & 'World'", False),
    ], 1, explanation="L'opérateur + joint deux chaînes.")
    add_fill(l2, "Quelle méthode met une chaîne en majuscules ? (ex: s.???())", "upper", 2,
             hint="Tout en capitales", explanation="upper() retourne la chaîne en majuscules.")
    add_tf(l2, "Les chaînes Python sont immuables.", True, 3,
           explanation="On ne peut pas modifier une chaîne en place, seulement en créer une nouvelle.")

    l3 = create_lesson(u1, "Nombres et opérations", "int, float et opérateurs arithmétiques", 3, 30)
    add_mc(l3, "Quel opérateur donne le reste d'une division ?", [
        ("/", False), ("//", False), ("%", True), ("**", False),
    ], 0, explanation="% est le modulo (reste de la division euclidienne).")
    add_mc(l3, "2 ** 3 en Python vaut :", [
        ("6", False), ("8", True), ("9", False), ("5", False),
    ], 1, explanation="** est l'exposant : 2³ = 8.")
    add_tf(l3, "10 / 3 retourne un float en Python 3.", True, 2,
           explanation="La division / retourne toujours un float, même si le résultat est entier.")
    add_code(l3, "Affichez le double de 21 (uniquement le nombre)", "print(21 * 2)", "42", 3,
             hint="Multipliez 21 par 2", explanation="21 * 2 = 42.")

    # --- Unité 2 : Conditions & Boucles ---
    u2 = create_unit(track, "Conditions & Boucles", "Contrôler le flux d'exécution", 2)

    l4 = create_lesson(u2, "Conditions if/elif/else", "Prendre des décisions dans le code", 1, 30)
    add_mc(l4, "Quel mot-clé teste une condition en Python ?", [
        ("when", False), ("if", True), ("switch", False), ("case", False),
    ], 0, explanation="if introduit un bloc conditionnel.")
    add_mc(l4, "Quelle indentation utilise Python pour les blocs ?", [
        ("Accolades {}", False), ("Tabulations/espaces", True), ("begin/end", False), ("parenthèses ()", False),
    ], 1, explanation="Python utilise l'indentation (4 espaces recommandés).")
    add_tf(l4, "elif est une abréviation de 'else if'.", True, 2,
           explanation="elif permet de chaîner plusieurs conditions.")
    add_code(l4, "Affichez 'pair' si 4 % 2 == 0 (utilisez if)", "if 4 % 2 == 0:\n    print('pair')", "pair", 3,
             explanation="4 est pair, donc le bloc if s'exécute.")

    l5 = create_lesson(u2, "Boucles for et while", "Répéter des actions", 2, 30)
    add_mc(l5, "range(3) génère les nombres :", [
        ("1, 2, 3", False), ("0, 1, 2", True), ("0, 1, 2, 3", False), ("3, 2, 1", False),
    ], 0, explanation="range(n) va de 0 à n-1.")
    add_mc(l5, "Quelle boucle s'exécute tant qu'une condition est vraie ?", [
        ("for", False), ("while", True), ("loop", False), ("repeat", False),
    ], 1, explanation="while continue tant que la condition est True.")
    add_tf(l5, "break permet de sortir immédiatement d'une boucle.", True, 2,
           explanation="break interrompt la boucle en cours.")
    add_code(l5, "Affichez 0, 1, 2 chacun sur une ligne", "for i in range(3):\n    print(i)", "0\n1\n2", 3,
             explanation="range(3) produit 0, 1, 2.")

    l6 = create_lesson(u2, "Premier programme Python", "Écrivez vos premiers scripts", 3, 40)
    add_code(l6, "Affichez exactement : Bonjour CodeQuest", 'print("Bonjour CodeQuest")', "Bonjour CodeQuest", 0,
             hint="Utilisez print()", explanation="print() affiche du texte.")
    add_code(l6, "Affichez la somme de 7 et 5 (uniquement le nombre)", "# Votre code\n", "12", 1,
             hint="print(7 + 5)", explanation="7 + 5 = 12.")
    add_code(l6, "Affichez les nombres 1 à 3, un par ligne", "for i in range(1, 4):\n    print(i)", "1\n2\n3", 2,
             explanation="range(1, 4) génère 1, 2, 3.")

    # --- Unité 3 : Structures de données ---
    u3 = create_unit(track, "Structures de données", "Listes, tuples et dictionnaires", 3)

    l7 = create_lesson(u3, "Les listes", "Collections ordonnées et modifiables", 1, 30)
    add_mc(l7, "Comment crée-t-on une liste vide ?", [
        ("list{}", False), ("[]", True), ("()", False), ("{}", False),
    ], 0, explanation="[] crée une liste vide.")
    add_mc(l7, "Comment accède-t-on au premier élément de liste L ?", [
        ("L[0]", True), ("L[1]", False), ("L.first()", False), ("L(0)", False),
    ], 1, explanation="L'indexation commence à 0 en Python.")
    add_tf(l7, "append() ajoute un élément à la fin d'une liste.", True, 2,
           explanation="ma_liste.append(x) ajoute x en fin de liste.")
    add_code(l7, "Créez une liste [1,2,3] et affichez sa longueur", "L = [1, 2, 3]\nprint(len(L))", "3", 3,
             explanation="len() retourne le nombre d'éléments.")

    l8 = create_lesson(u3, "Les dictionnaires", "Paires clé-valeur", 2, 30)
    add_mc(l8, "Comment crée-t-on un dictionnaire vide ?", [
        ("[]", False), ("{}", True), ("dict[]", False), ("()", False),
    ], 0, explanation="{} crée un dict vide.")
    add_mc(l8, "Comment accède-t-on à la valeur de la clé 'nom' ?", [
        ("d.nom", False), ("d['nom']", True), ("d->nom", False), ("d(nom)", False),
    ], 1, explanation="d['clé'] accède à une valeur.")
    add_fill(l8, "Quelle méthode retourne toutes les clés d'un dict ? (d.???())", "keys", 2,
             explanation="keys() retourne les clés du dictionnaire.")
    add_code(l8, "Affichez la valeur de {'a': 1, 'b': 2} pour la clé 'a'", "d = {'a': 1, 'b': 2}\nprint(d['a'])", "1", 3,
             explanation="d['a'] vaut 1.")


def load_reseaux():
    track = create_track(
        "Réseaux & TCP/IP",
        "reseaux-tcpip",
        "Adressage IP, protocoles, OSI et services réseau.",
        "🌐",
        "#1CB0F6",
        2,
    )

    u1 = create_unit(track, "Adressage IP", "IPv4, masques et sous-réseaux", 1)

    l1 = create_lesson(u1, "IPv4 — Les bases", "Structure d'une adresse IPv4", 1, 30)
    add_mc(l1, "Combien d'octets comporte une adresse IPv4 ?", [
        ("2", False), ("4", True), ("6", False), ("8", False),
    ], 0, explanation="IPv4 = 4 octets = 32 bits.")
    add_mc(l1, "Quelle adresse est une adresse privée (RFC 1918) ?", [
        ("8.8.8.8", False), ("192.168.1.1", True), ("1.1.1.1", False), ("142.250.0.0", False),
    ], 1, explanation="192.168.x.x est dans l'espace privé.")
    add_fill(l1, "Quel protocole résout un nom de domaine en IP ?", "dns", 2,
             explanation="DNS = Domain Name System.")
    add_tf(l1, "127.0.0.1 est l'adresse de bouclage (localhost).", True, 3,
           explanation="localhost pointe vers la machine locale.")

    l2 = create_lesson(u1, "Masques et sous-réseaux", "Découper un réseau", 2, 35)
    add_mc(l2, "Un masque /24 laisse combien d'hôtes utilisables (classique) ?", [
        ("254", True), ("256", False), ("255", False), ("512", False),
    ], 0, explanation="/24 = 256 adresses, 254 utilisables (moins réseau et broadcast).")
    add_mc(l2, "Quel masque correspond à /24 ?", [
        ("255.255.0.0", False), ("255.255.255.0", True), ("255.0.0.0", False), ("255.255.255.255", False),
    ], 1, explanation="255.255.255.0 = 24 bits réseau.")
    add_tf(l2, "Le CIDR notation utilise un slash suivi du nombre de bits réseau.", True, 2,
           explanation="Ex: 192.168.1.0/24.")
    add_mc(l2, "Quel protocole attribue automatiquement une IP ?", [
        ("DNS", False), ("DHCP", True), ("HTTP", False), ("FTP", False),
    ], 3, explanation="DHCP attribue IP, masque, passerelle, DNS.")

    l3 = create_lesson(u1, "IPv6", "Le successeur d'IPv4", 3, 30)
    add_mc(l3, "Combien de bits comporte une adresse IPv6 ?", [
        ("32", False), ("64", False), ("128", True), ("256", False),
    ], 0, explanation="IPv6 utilise 128 bits.")
    add_tf(l3, "IPv6 résout le problème d'épuisement des adresses IPv4.", True, 1,
           explanation="2^128 adresses disponibles.")
    add_fill(l3, "Quel type d'enregistrement DNS mappe un nom vers une IPv6 ? (AAAA ou ???)", "aaaa", 2,
             hint="4 fois la lettre A", explanation="AAAA pour IPv6, A pour IPv4.")

    u2 = create_unit(track, "Protocoles & Modèle OSI", "TCP, UDP, HTTP et les 7 couches", 2)

    l4 = create_lesson(u2, "TCP vs UDP", "Protocoles de transport", 1, 30)
    add_mc(l4, "Quel protocole garantit la livraison et l'ordre des paquets ?", [
        ("UDP", False), ("TCP", True), ("ICMP", False), ("ARP", False),
    ], 0, explanation="TCP est orienté connexion et fiable.")
    add_mc(l4, "Quel protocole est plus rapide mais sans garantie ?", [
        ("TCP", False), ("UDP", True), ("HTTPS", False), ("SMTP", False),
    ], 1, explanation="UDP est léger, idéal pour streaming/jeux.")
    add_tf(l4, "Le port 80 est le port par défaut de HTTP.", True, 2,
           explanation="HTTP utilise le port 80, HTTPS le 443.")
    add_mc(l4, "Quel protocole utilise le port 443 ?", [
        ("HTTP", False), ("HTTPS", True), ("FTP", False), ("SSH", False),
    ], 3, explanation="HTTPS = HTTP + TLS sur le port 443.")

    l5 = create_lesson(u2, "Le modèle OSI", "Les 7 couches réseau", 2, 35)
    add_mc(l5, "Combien de couches compte le modèle OSI ?", [
        ("4", False), ("5", False), ("7", True), ("9", False),
    ], 0, explanation="OSI : Physique, Liaison, Réseau, Transport, Session, Présentation, Application.")
    add_mc(l5, "À quelle couche OSI appartient IP ?", [
        ("Couche 2", False), ("Couche 3", True), ("Couche 4", False), ("Couche 7", False),
    ], 1, explanation="IP est à la couche Réseau (3).")
    add_fill(l5, "Quel protocole de couche 2 utilise des adresses MAC ?", "ethernet", 2,
             hint="Très courant sur LAN", explanation="Ethernet associe des adresses MAC.")
    add_tf(l5, "HTTP est un protocole de couche Application (couche 7).", True, 3,
           explanation="HTTP opère au niveau application.")


def load_cybersecurite():
    track = create_track(
        "Cybersécurité",
        "cybersecurite",
        "OWASP, authentification, chiffrement et bonnes pratiques.",
        "🔒",
        "#FF4B4B",
        3,
    )

    u1 = create_unit(track, "OWASP Top 10", "Vulnérabilités web critiques", 1)

    l1 = create_lesson(u1, "Injection SQL", "Comprendre et prévenir les injections", 1, 35)
    add_tf(l1, "L'injection SQL exploite des requêtes non paramétrées.", True, 0,
           explanation="Les requêtes préparées neutralisent ce risque.")
    add_mc(l1, "Quelle est la meilleure défense contre l'injection SQL ?", [
        ("Échapper les guillemets manuellement", False),
        ("Requêtes préparées (paramétrées)", True),
        ("Cacher la base de données", False),
        ("Utiliser HTTP au lieu de HTTPS", False),
    ], 1, explanation="Les ORM et requêtes paramétrées séparent code et données.")
    add_fill(l1, "Quel caractère est souvent utilisé pour terminer une requête SQL en injection ? (;)", ";", 2,
             hint="Point-virgule", explanation="; termine une instruction SQL.")
    add_tf(l1, "Valider les entrées côté serveur est essentiel.", True, 3,
           explanation="Ne jamais faire confiance aux données utilisateur.")

    l2 = create_lesson(u1, "Cross-Site Scripting (XSS)", "Injecter du JavaScript malveillant", 2, 35)
    add_tf(l2, "Le XSS permet d'exécuter du code dans le navigateur de la victime.", True, 0,
           explanation="XSS injecte du script exécuté côté client.")
    add_mc(l2, "Comment prévenir le XSS stocké ?", [
        ("Désactiver JavaScript", False), ("Échapper/encoder les sorties HTML", True),
        ("Utiliser HTTP", False), ("Supprimer les cookies", False),
    ], 1, explanation="Encoder <, >, &, \" empêche l'exécution de scripts.")
    add_tf(l2, "Content-Security-Policy (CSP) aide à mitiger le XSS.", True, 2,
           explanation="CSP restreint les sources de scripts autorisées.")
    add_mc(l2, "Quel type de XSS est reflété dans l'URL ?", [
        ("Stocké", False), ("Réfléchi", True), ("DOM", False), ("Persistant", False),
    ], 3, explanation="XSS réfléchi : payload dans la requête, renvoyé dans la réponse.")

    l3 = create_lesson(u1, "CSRF et authentification", "Protéger les sessions", 3, 35)
    add_tf(l3, "CSRF force un utilisateur authentifié à exécuter une action non voulue.", True, 0,
           explanation="Ex: transfert bancaire déclenché à son insu.")
    add_mc(l3, "Quel token protège contre le CSRF ?", [
        ("JWT access token", False), ("Token CSRF synchronisé", True),
        ("Cookie de session seul", False), ("Adresse IP", False),
    ], 1, explanation="Un token secret par formulaire valide l'origine.")
    add_mc(l3, "Quel attribut cookie limite l'envoi cross-site ?", [
        ("HttpOnly", False), ("SameSite", True), ("Secure", False), ("Domain", False),
    ], 2, explanation="SameSite=Strict/Lax réduit les requêtes cross-origin.")
    add_tf(l3, "MFA (authentification multi-facteurs) renforce la sécurité des comptes.", True, 3,
           explanation="Mot de passe + TOTP/SMS/biométrie.")

    u2 = create_unit(track, "Cryptographie", "Hash, chiffrement et certificats", 2)

    l4 = create_lesson(u2, "Hash vs Chiffrement", "Intégrité et confidentialité", 1, 35)
    add_mc(l4, "Une fonction de hachage est-elle réversible ?", [
        ("Oui, toujours", False), ("Non, c'est à sens unique", True),
        ("Oui, avec la clé privée", False), ("Non, sauf pour MD5", False),
    ], 0, explanation="Le hash est irréversible par conception.")
    add_mc(l4, "Quel algorithme de hash est recommandé aujourd'hui pour les mots de passe ?", [
        ("MD5", False), ("SHA-1", False), ("bcrypt/Argon2", True), ("Base64", False),
    ], 1, explanation="bcrypt et Argon2 sont lents volontairement (anti brute-force).")
    add_tf(l4, "AES est un algorithme de chiffrement symétrique.", True, 2,
           explanation="AES utilise la même clé pour chiffrer et déchiffrer.")
    add_fill(l4, "Quel protocole sécurise HTTP ? (???)", "https", 3,
             explanation="HTTPS = HTTP + TLS.")

    l5 = create_lesson(u2, "Certificats TLS", "PKI et confiance", 2, 30)
    add_mc(l5, "Qui émet les certificats TLS de confiance ?", [
        ("L'utilisateur", False), ("Autorité de Certification (CA)", True),
        ("Le navigateur", False), ("Le routeur", False),
    ], 0, explanation="Les CA signent les certificats.")
    add_tf(l5, "Un certificat auto-signé génère un avertissement navigateur.", True, 1,
           explanation="Pas de chaîne de confiance vers une CA reconnue.")
    add_mc(l5, "Quelle clé chiffre les données en TLS (échange hybride) ?", [
        ("Clé publique du serveur pour tout", False),
        ("Clé de session symétrique", True),
        ("Clé privée du client", False), ("Hash SHA-256", False),
    ], 2, explanation="TLS utilise RSA/ECDHE puis AES avec clé de session.")


def load_web_dev():
    track = create_track(
        "Développement Web",
        "developpement-web",
        "HTML, CSS, JavaScript et les bases du web moderne.",
        "🌍",
        "#CE82FF",
        4,
    )

    u1 = create_unit(track, "HTML & CSS", "Structure et style des pages web", 1)

    l1 = create_lesson(u1, "Structure HTML", "Les balises essentielles", 1, 25)
    add_mc(l1, "Quelle balise contient le contenu visible de la page ?", [
        ("<head>", False), ("<body>", True), ("<meta>", False), ("<link>", False),
    ], 0, explanation="<body> contient le contenu affiché.")
    add_mc(l1, "Quelle balise crée un lien hypertexte ?", [
        ("<link>", False), ("<a>", True), ("<href>", False), ("<url>", False),
    ], 1, explanation="<a href='...'> crée un lien.")
    add_fill(l1, "Quelle balise insère une image ? (???)", "img", 2,
             hint="3 lettres", explanation="<img src='...' alt='...'>")
    add_tf(l1, "HTML5 est la version actuelle du langage HTML.", True, 3,
           explanation="HTML5 apporte sémantique et APIs modernes.")

    l2 = create_lesson(u1, "CSS — Les bases", "Mettre en forme les pages", 2, 30)
    add_mc(l2, "Que signifie CSS ?", [
        ("Computer Style Sheets", False), ("Cascading Style Sheets", True),
        ("Creative Style System", False), ("Color Style Syntax", False),
    ], 0, explanation="CSS = feuilles de style en cascade.")
    add_mc(l2, "Quel sélecteur cible un élément par son id ?", [
        (".monId", False), ("#monId", True), ("*monId", False), ("@monId", False),
    ], 1, explanation="#id cible un identifiant unique.")
    add_tf(l2, "display: flex facilite les mises en page flexibles.", True, 2,
           explanation="Flexbox aligne et distribue l'espace.")
    add_fill(l2, "Quelle propriété change la couleur du texte ? (color ou ???)", "color", 3,
             explanation="color définit la couleur du texte.")

    u2 = create_unit(track, "JavaScript", "Interactivité côté client", 2)

    l3 = create_lesson(u2, "JavaScript — Fondamentaux", "Variables et fonctions", 1, 30)
    add_mc(l3, "Quel mot-clé déclare une constante en JS moderne ?", [
        ("var", False), ("const", True), ("static", False), ("define", False),
    ], 0, explanation="const pour les constantes, let pour les variables.")
    add_mc(l3, "Comment déclare-t-on une fonction fléchée ?", [
        ("function => ()", False), ("() => {}", True), ("def () {}", False), ("fn () ->", False),
    ], 1, explanation="() => {} est la syntaxe arrow function.")
    add_tf(l3, "JavaScript s'exécute dans le navigateur et sur Node.js.", True, 2,
           explanation="JS est multiplateforme.")
    add_mc(l3, "Quelle méthode sélectionne un élément par son id ?", [
        ("document.query()", False), ("document.getElementById()", True),
        ("document.find()", False), ("window.select()", False),
    ], 3, explanation="getElementById('monId') retourne l'élément.")

    l4 = create_lesson(u2, "DOM et événements", "Réagir aux actions utilisateur", 2, 30)
    add_mc(l4, "Que signifie DOM ?", [
        ("Data Object Model", False), ("Document Object Model", True),
        ("Dynamic Output Method", False), ("Document Oriented Markup", False),
    ], 0, explanation="DOM = représentation objet de la page HTML.")
    add_tf(l4, "addEventListener permet d'écouter les clics sur un élément.", True, 1,
           explanation="element.addEventListener('click', handler).")
    add_fill(l4, "Quelle méthode empêche le rechargement d'un formulaire ? (prevent???)", "preventdefault", 2,
             hint="event.prevent...", explanation="event.preventDefault() annule l'action par défaut.")
    add_mc(l4, "Quel événement se déclenche quand la page est chargée ?", [
        ("onhover", False), ("DOMContentLoaded", True), ("onscroll", False), ("onresize", False),
    ], 3, explanation="DOMContentLoaded : DOM prêt à manipuler.")


def load_linux():
    track = create_track(
        "Linux & Systèmes",
        "linux-systemes",
        "Commandes essentielles, permissions et administration.",
        "🐧",
        "#FCC624",
        5,
    )

    u1 = create_unit(track, "Commandes de base", "Naviguer et manipuler les fichiers", 1)

    l1 = create_lesson(u1, "Navigation", "Se déplacer dans l'arborescence", 1, 25)
    add_mc(l1, "Quelle commande affiche le répertoire courant ?", [
        ("ls", False), ("pwd", True), ("cd", False), ("dir", False),
    ], 0, explanation="pwd = Print Working Directory.")
    add_mc(l1, "Quelle commande liste les fichiers ?", [
        ("list", False), ("ls", True), ("show", False), ("cat", False),
    ], 1, explanation="ls liste le contenu d'un répertoire.")
    add_fill(l1, "Quelle commande change de répertoire ? (??)", "cd", 2,
             explanation="cd /chemin/vers/dossier")
    add_tf(l1, "cd .. remonte au répertoire parent.", True, 3,
           explanation=".. représente le dossier parent.")

    l2 = create_lesson(u1, "Fichiers et dossiers", "Créer, copier, supprimer", 2, 30)
    add_mc(l2, "Quelle commande crée un répertoire ?", [
        ("mkdir", True), ("touch", False), ("mkfile", False), ("newdir", False),
    ], 0, explanation="mkdir nom_dossier")
    add_mc(l2, "Quelle commande affiche le contenu d'un fichier texte ?", [
        ("show", False), ("cat", True), ("type", False), ("read", False),
    ], 1, explanation="cat fichier.txt affiche le contenu.")
    add_tf(l2, "rm -rf supprime récursivement sans confirmation.", True, 2,
           explanation="Attention : -rf est destructif !")
    add_mc(l2, "Quelle commande copie un fichier ?", [
        ("mv", False), ("cp", True), ("copy", False), ("scp uniquement", False),
    ], 3, explanation="cp source destination")

    u2 = create_unit(track, "Permissions", "Utilisateurs, groupes et droits", 2)

    l3 = create_lesson(u2, "Permissions Unix", "rwx et chmod", 1, 35)
    add_mc(l3, "Que signifie rwx ?", [
        ("read, write, execute", True), ("root, write, exit", False),
        ("run, wait, exit", False), ("read, wait, export", False),
    ], 0, explanation="r=lire, w=écrire, x=exécuter.")
    add_mc(l3, "chmod 755 donne quels droits au propriétaire ?", [
        ("r-x", False), ("rwx", True), ("rw-", False), ("---", False),
    ], 1, explanation="7=rwx, 5=r-x, 5=r-x")
    add_tf(l3, "Le superutilisateur Linux s'appelle root.", True, 2,
           explanation="root a tous les privilèges (UID 0).")
    add_fill(l3, "Quelle commande change le propriétaire d'un fichier ? (ch???)", "chown", 3,
             explanation="chown user:group fichier")


def load_bases_de_donnees():
    track = create_track(
        "Bases de données SQL",
        "bases-de-donnees",
        "Requêtes SQL, relations et bonnes pratiques.",
        "🗄️",
        "#FF9600",
        6,
    )

    u1 = create_unit(track, "SQL Fondamental", "Lire et écrire des données", 1)

    l1 = create_lesson(u1, "SELECT et WHERE", "Interroger une table", 1, 30)
    add_mc(l1, "Quelle clause filtre les lignes ?", [
        ("FILTER", False), ("WHERE", True), ("HAVING", False), ("LIMIT", False),
    ], 0, explanation="WHERE conditionne les lignes retournées.")
    add_mc(l1, "SELECT * FROM users récupère :", [
        ("Uniquement l'id", False), ("Toutes les colonnes", True),
        ("Le nombre de lignes", False), ("Les index", False),
    ], 1, explanation="* = toutes les colonnes.")
    add_fill(l1, "Quel mot-clé trie les résultats ? (ORDER BY ou ??? seul)", "order", 2,
             hint="Ordre croissant/décroissant", explanation="ORDER BY colonne ASC/DESC")
    add_tf(l1, "SQL est un langage déclaratif.", True, 3,
           explanation="On décrit QUOI on veut, pas COMMENT.")

    l2 = create_lesson(u1, "INSERT, UPDATE, DELETE", "Modifier les données", 2, 30)
    add_mc(l2, "Quelle commande ajoute une ligne ?", [
        ("ADD", False), ("INSERT INTO", True), ("CREATE ROW", False), ("APPEND", False),
    ], 0, explanation="INSERT INTO table (cols) VALUES (vals)")
    add_tf(l2, "UPDATE modifie des lignes existantes.", True, 1,
           explanation="UPDATE table SET col=val WHERE condition")
    add_mc(l2, "DELETE sans WHERE :", [
        ("Supprime une ligne aléatoire", False), ("Supprime toutes les lignes", True),
        ("Ne fait rien", False), ("Supprime la table", False),
    ], 2, explanation="DELETE sans WHERE = suppression totale !")
    add_fill(l2, "Quelle clause regroupe les lignes pour agrégation ? (GROUP ???)", "by", 3,
             explanation="GROUP BY colonne")

    l3 = create_lesson(u1, "Relations et JOIN", "Lier plusieurs tables", 3, 35)
    add_mc(l3, "Quel JOIN retourne uniquement les correspondances ?", [
        ("LEFT JOIN", False), ("INNER JOIN", True), ("FULL JOIN", False), ("CROSS JOIN", False),
    ], 0, explanation="INNER JOIN : intersection des deux tables.")
    add_tf(l3, "Une clé primaire identifie uniquement chaque ligne.", True, 1,
           explanation="PRIMARY KEY garantit l'unicité.")
    add_mc(l3, "Une clé étrangère (FOREIGN KEY) :", [
        ("Chiffre les données", False), ("Référence une clé primaire d'une autre table", True),
        ("Indexe automatiquement", False), ("Supprime les doublons", False),
    ], 2, explanation="FK assure l'intégrité référentielle.")
    add_fill(l3, "Quel type de relation lie un auteur à plusieurs livres ? (one-to-???)", "many", 3,
             hint="Un à plusieurs", explanation="One-to-many : 1 auteur, N livres.")


def load_git():
    track = create_track(
        "Git & Collaboration",
        "git-collaboration",
        "Versionnement, branches et travail en équipe.",
        "📦",
        "#F05032",
        7,
    )

    u1 = create_unit(track, "Git Essentiel", "Versionner son code", 1)

    l1 = create_lesson(u1, "Les bases de Git", "init, add, commit", 1, 25)
    add_mc(l1, "Quelle commande initialise un dépôt Git ?", [
        ("git start", False), ("git init", True), ("git new", False), ("git create", False),
    ], 0, explanation="git init crée le dossier .git")
    add_mc(l1, "git add met les fichiers dans :", [
        ("Le commit", False), ("La staging area (index)", True),
        ("La branche main", False), ("Le remote", False),
    ], 1, explanation="add prépare les fichiers pour le commit.")
    add_fill(l1, "Quelle commande enregistre un snapshot ? (git ???)", "commit", 2,
             explanation="git commit -m 'message'")
    add_tf(l1, "Chaque commit a un hash SHA unique.", True, 3,
           explanation="L'historique est une chaîne de commits identifiés.")

    l2 = create_lesson(u1, "Branches et fusion", "Travailler en parallèle", 2, 30)
    add_mc(l2, "Quelle commande crée et bascule sur une branche ?", [
        ("git branch new", False), ("git checkout -b feature", True),
        ("git switch create", False), ("git new branch", False),
    ], 0, explanation="git checkout -b nom ou git switch -c nom")
    add_tf(l2, "git merge fusionne une branche dans la branche courante.", True, 1,
           explanation="merge intègre les commits d'une branche.")
    add_mc(l2, "Qu'est-ce qu'un conflit de merge ?", [
        ("Une erreur réseau", False), ("Deux modifications incompatibles sur la même ligne", True),
        ("Un commit vide", False), ("Une branche supprimée", False),
    ], 2, explanation="Git ne peut pas fusionner automatiquement.")
    add_fill(l2, "Quelle plateforme héberge des dépôts Git populaires ? (Git???)", "github", 3,
             explanation="GitHub, GitLab, Bitbucket...")


def load_algorithmique():
    """Parcours 8 — Apprendre à raisonner étape par étape (très progressif)."""
    track = create_track(
        "Algorithmique & Logique",
        "algorithmique-logique",
        "Apprenez à décomposer un problème en étapes claires, comme un chef de cuisine suit une recette.",
        "🧠",
        "#9B59B6",
        8,
    )

    u1 = create_unit(
        track,
        "Étape 1 — Qu'est-ce qu'un algorithme ?",
        "Avant de coder, on apprend à décrire une solution dans l'ordre",
        1,
    )

    l1 = create_lesson(
        u1,
        "La recette du programmeur",
        "Un algorithme, c'est une suite d'instructions précises pour atteindre un objectif",
        1,
        25,
    )
    add_mc(
        l1,
        "Un algorithme, c'est avant tout :",
        [
            ("Un langage de programmation", False),
            ("Une suite d'étapes ordonnées pour résoudre un problème", True),
            ("Un fichier exécutable", False),
            ("Une base de données", False),
        ],
        0,
        hint="Pensez à une recette de cuisine : étape 1, étape 2…",
        explanation="Comme une recette, un algorithme décrit QUOI faire, dans quel ordre, "
                    "sans se soucier encore du langage (Python, Java…).",
    )
    add_tf(
        l1,
        "Un algorithme doit être fini : il s'arrête après un nombre d'étapes raisonnable.",
        True,
        1,
        hint="Une boucle infinie n'est pas un bon algorithme",
        explanation="Un algorithme valide termine toujours. Sinon, l'ordinateur tournerait sans fin.",
    )
    add_mc(
        l1,
        "Quels sont les trois éléments classiques d'un algorithme ?",
        [
            ("Entrée, traitement, sortie", True),
            ("HTML, CSS, JavaScript", False),
            ("CPU, RAM, disque", False),
            ("Client, serveur, API", False),
        ],
        2,
        hint="Données reçues → calcul → résultat",
        explanation="Exemple : entrée = liste de notes, traitement = calcul de la moyenne, "
                    "sortie = la moyenne affichée.",
    )
    add_fill(
        l1,
        "Le pseudo-code utilise un langage proche de l'humain, sans syntaxe stricte. "
        "Comment appelle-t-on cette étape intermédiaire avant le code ? (pseudo-???)",
        "code",
        3,
        hint="Deux mots : pseudo + …",
        explanation="Le pseudo-code aide à réfléchir sans se bloquer sur les détails du langage.",
    )

    l2 = create_lesson(
        u1,
        "Décomposer un problème",
        "La compétence clé : diviser un gros problème en petites tâches",
        2,
        30,
    )
    add_mc(
        l2,
        "Pour « faire un sandwich », quelle est la BONNE approche algorithmique ?",
        [
            ("Tout faire en une seule étape floue", False),
            ("Lister : prendre pain → garnir → refermer → servir", True),
            ("Commencer par servir puis garnir", False),
            ("Ignorer l'ordre des étapes", False),
        ],
        0,
        explanation="Chaque étape est simple et vérifiable. C'est le principe de la décomposition.",
    )
    add_tf(
        l2,
        "Plus un problème est découpé en petites étapes, plus il devient facile à coder et à tester.",
        True,
        1,
        explanation="C'est la base du développement : une fonction = une responsabilité.",
    )
    add_mc(
        l2,
        "Quelle structure permet de répéter une action tant qu'une condition est vraie ?",
        [
            ("if", False),
            ("while / boucle", True),
            ("print", False),
            ("import", False),
        ],
        2,
        hint="Vous l'avez vu en Python : while …",
        explanation="Les boucles automatisent les répétitions — essentiel en algorithmique.",
    )
    add_mc(
        l2,
        "Si un algorithme doit traiter 1000 éléments un par un, on parle de :",
        [
            ("Parcours (itération)", True),
            ("Compilation", False),
            ("Chiffrement", False),
            ("Formatage disque", False),
        ],
        3,
        explanation="Parcourir une collection élément par élément est l'opération la plus courante.",
    )

    u2 = create_unit(
        track,
        "Étape 2 — Parcourir et chercher",
        "Comment trouver une aiguille dans une botte de foin (méthode simple)",
        2,
    )

    l3 = create_lesson(
        u2,
        "La recherche linéaire",
        "On examine chaque élément, un par un, de gauche à droite",
        1,
        30,
    )
    add_mc(
        l3,
        "Dans une liste [3, 7, 2, 9], combien d'éléments faut-il examiner au pire pour trouver 9 ?",
        [
            ("1", False),
            ("4", True),
            ("9", False),
            ("2", False),
        ],
        0,
        hint="Le 9 est en dernière position",
        explanation="Recherche linéaire : au pire, on parcourt toute la liste (4 éléments ici).",
    )
    add_tf(
        l3,
        "La recherche linéaire fonctionne même si la liste n'est pas triée.",
        True,
        1,
        explanation="Pas besoin d'ordre : on compare chaque élément jusqu'à trouver.",
    )
    add_mc(
        l3,
        "Quelle est la complexité intuitive de la recherche linéaire sur n éléments ?",
        [
            ("On regarde au plus n éléments", True),
            ("On regarde toujours 1 élément", False),
            ("On regarde log(n) éléments", False),
            ("On ne regarde aucun élément", False),
        ],
        2,
        hint="Plus la liste est longue, plus on peut avoir d'étapes",
        explanation="Notation O(n) : le temps grandit proportionnellement à la taille.",
    )
    add_code(
        l3,
        "Écrivez un programme qui affiche le maximum de [4, 1, 9, 3] (uniquement le nombre)",
        "nombres = [4, 1, 9, 3]\nprint(max(nombres))",
        "9",
        3,
        hint="Python a une fonction max()",
        explanation="max() parcourt la liste et retourne le plus grand — recherche linéaire interne.",
    )

    l4 = create_lesson(
        u2,
        "Minimum, maximum et comptage",
        "Trois opérations fondamentales sur une collection",
        2,
        35,
    )
    add_mc(
        l4,
        "Pour trouver le minimum d'une liste sans fonction intégrée, on peut :",
        [
            ("Comparer chaque élément au minimum courant", True),
            ("Trier d'abord la liste aléatoirement", False),
            ("Supprimer le premier élément", False),
            ("Multiplier tous les éléments", False),
        ],
        0,
        explanation="On initialise min = premier élément, puis on met à jour si on trouve plus petit.",
    )
    add_code(
        l4,
        "Affichez combien d'éléments contient la liste [10, 20, 30] (uniquement le nombre)",
        "print(len([10, 20, 30]))",
        "3",
        1,
        hint="len() compte les éléments",
        explanation="len() retourne la taille — opération en O(1) en Python pour une liste.",
    )
    add_code(
        l4,
        "Affichez la somme de [5, 5, 5] (uniquement le nombre)",
        "print(sum([5, 5, 5]))",
        "15",
        2,
        hint="sum() additionne tous les éléments",
        explanation="Parcourir et accumuler une somme est un pattern algorithmique classique.",
    )
    add_tf(
        l4,
        "Pour compter combien de fois « a » apparaît dans une liste, on parcourt toute la liste.",
        True,
        3,
        explanation="Comptage = parcours + condition + compteur qu'on incrémente.",
    )

    u3 = create_unit(
        track,
        "Étape 3 — Trier et comprendre l'efficacité",
        "Pourquoi l'ordre change la donne, et comment trier simplement",
        3,
    )

    l5 = create_lesson(
        u3,
        "Pourquoi trier ?",
        "Un tableau trié permet des recherches beaucoup plus rapides",
        1,
        30,
    )
    add_tf(
        l5,
        "Dans un dictionnaire alphabétique trié, trouver un mot est plus rapide qu'au hasard.",
        True,
        0,
        explanation="Analogie : le tri permet de « sauter » des sections entières (recherche dichotomique).",
    )
    add_mc(
        l5,
        "Le tri à bulles compare des paires adjacentes et les échange si nécessaire. "
        "C'est un algorithme :",
        [
            ("Simple à comprendre mais lent sur de grandes listes", True),
            ("Le plus rapide qui existe", False),
            ("Impossible à implémenter", False),
            ("Réservé aux experts", False),
        ],
        1,
        hint="Idéal pour apprendre, pas pour des millions de données",
        explanation="Tri à bulles = pédagogique. En production on utilise des tris plus efficaces (Timsort…).",
    )
    add_mc(
        l5,
        "Si une liste a 1 million d'éléments, un algorithme O(n²) sera :",
        [
            ("Probablement trop lent", True),
            ("Toujours instantané", False),
            ("Identique à O(n)", False),
            ("Impossible à mesurer", False),
        ],
        2,
        explanation="O(n²) = 10¹² opérations potentielles — d'où l'importance du choix d'algorithme.",
    )
    add_fill(
        l5,
        "La recherche dans une liste TRIÉE en coupant en deux à chaque étape s'appelle recherche "
        "???otomique (début du mot)",
        "dich",
        3,
        hint="Di… — diviser pour régner",
        explanation="Recherche dichotomique : O(log n) — très efficace sur données triées.",
    )

    l6 = create_lesson(
        u3,
        "Introduction douce à la récursion",
        "Une fonction qui s'appelle elle-même — avec prudence !",
        2,
        35,
    )
    add_mc(
        l6,
        "La récursion, c'est quand une fonction :",
        [
            ("S'appelle elle-même pour résoudre un sous-problème", True),
            ("Ne s'exécute jamais", False),
            ("Supprime le fichier source", False),
            ("Remplace les boucles obligatoirement", False),
        ],
        0,
        hint="factorielle(n) = n × factorielle(n-1)",
        explanation="Exemple classique : factorial(5) = 5 × factorial(4) × … × 1.",
    )
    add_tf(
        l6,
        "Toute récursion a besoin d'un cas de base pour s'arrêter.",
        True,
        1,
        explanation="Sans cas de base (ex: factorial(0)=1), la récursion ne finit jamais → stack overflow.",
    )
    add_mc(
        l6,
        "Quel est le cas de base de la factorielle ?",
        [
            ("0! = 1", True),
            ("0! = 0", False),
            ("1! = 0", False),
            ("Il n'y en a pas", False),
        ],
        2,
        explanation="0! = 1 par convention mathématique — c'est le point d'arrêt de la récursion.",
    )
    add_code(
        l6,
        "Affichez les nombres de 3 à 1 en compte à rebours (un par ligne)",
        "for i in range(3, 0, -1):\n    print(i)",
        "3\n2\n1",
        3,
        hint="range(3, 0, -1) compte à rebours",
        explanation="Avant la récursion pure, maîtriser les boucles et l'ordre des étapes est essentiel.",
    )


def load_docker():
    """Parcours 9 — Docker expliqué simplement, du concept à la pratique."""
    track = create_track(
        "Docker & Conteneurs",
        "docker-conteneurs",
        "Comprenez les conteneurs comme des boîtes légères qui emballent votre application "
        "avec tout ce dont elle a besoin pour tourner partout.",
        "🐳",
        "#2496ED",
        9,
    )

    u1 = create_unit(
        track,
        "Étape 1 — Pourquoi Docker ?",
        "Le problème « ça marche sur ma machine » et comment Docker le résout",
        1,
    )

    l1 = create_lesson(
        u1,
        "VM vs Conteneur — La différence clé",
        "Une VM virtualise tout un OS ; un conteneur partage le noyau Linux",
        1,
        30,
    )
    add_mc(
        l1,
        "Une machine virtuelle (VM) contient :",
        [
            ("Un système d'exploitation complet invité", True),
            ("Uniquement votre application, sans OS", False),
            ("Seulement du HTML", False),
            ("Uniquement une base de données", False),
        ],
        0,
        hint="VM = ordinateur virtuel complet",
        explanation="Une VM est lourde (Go de disque, minutes pour démarrer). "
                    "Elle embarque son propre noyau/OS.",
    )
    add_mc(
        l1,
        "Un conteneur Docker :",
        [
            ("Partage le noyau de l'hôte et isole l'application", True),
            ("Contient un Windows complet", False),
            ("Ne peut pas être démarré", False),
            ("Remplace Git", False),
        ],
        1,
        hint="Plus léger qu'une VM",
        explanation="Conteneur = processus isolé + filesystem isolé. Démarrage en secondes.",
    )
    add_tf(
        l1,
        "Docker aide à garantir que l'app tourne pareil en dev, test et production.",
        True,
        2,
        explanation="Même image = même environnement. Fini « chez moi ça marche ».",
    )
    add_mc(
        l1,
        "Quelle analogie décrit le mieux une image Docker ?",
        [
            ("Une recette figée (modèle) à partir de laquelle on crée des plats", True),
            ("Un câble réseau", False),
            ("Un mot de passe", False),
            ("Un fichier .docx", False),
        ],
        3,
        hint="Image = modèle ; conteneur = instance en cours d'exécution",
        explanation="Image = gabarit immuable. Conteneur = instance vivante créée depuis l'image.",
    )

    l2 = create_lesson(
        u1,
        "Images et conteneurs",
        "Image = la recette. Conteneur = le plat servi.",
        2,
        30,
    )
    add_mc(
        l2,
        "Quelle commande télécharge une image depuis Docker Hub ?",
        [
            ("docker pull nginx", True),
            ("docker run nginx", False),
            ("docker get nginx", False),
            ("docker download nginx", False),
        ],
        0,
        explanation="docker pull télécharge l'image. docker run la télécharge si absente, puis lance.",
    )
    add_mc(
        l2,
        "Quelle commande liste les conteneurs EN COURS d'exécution ?",
        [
            ("docker ps", True),
            ("docker images", False),
            ("docker list", False),
            ("docker show", False),
        ],
        1,
        hint="ps = process status",
        explanation="docker ps = conteneurs actifs. docker ps -a = tous (y compris arrêtés).",
    )
    add_tf(
        l2,
        "Un conteneur arrêté conserve ses modifications dans une couche writable.",
        True,
        2,
        explanation="Les données écrites dans le conteneur peuvent être perdues si non persistées (volumes).",
    )
    add_fill(
        l2,
        "Pour arrêter proprement un conteneur : docker ??? <id>",
        "stop",
        3,
        hint="L'inverse de start",
        explanation="docker stop envoie SIGTERM puis arrête le conteneur.",
    )

    u2 = create_unit(
        track,
        "Étape 2 — Commandes du quotidien",
        "Lancer, publier des ports, inspecter — pas à pas",
        2,
    )

    l3 = create_lesson(
        u2,
        "Lancer son premier conteneur",
        "docker run : créer et démarrer en une commande",
        1,
        35,
    )
    add_mc(
        l3,
        "docker run -d -p 8080:80 nginx signifie :",
        [
            ("Lancer nginx en arrière-plan, port hôte 8080 → port conteneur 80", True),
            ("Supprimer nginx", False),
            ("Compiler nginx", False),
            ("Chiffrer le port 80", False),
        ],
        0,
        hint="-d = detached (arrière-plan), -p = port mapping",
        explanation="-p 8080:80 redirige localhost:8080 vers le port 80 du conteneur.",
    )
    add_mc(
        l3,
        "Que fait l'option -d de docker run ?",
        [
            ("Lance en arrière-plan (detached)", True),
            ("Supprime l'image", False),
            ("Active le mode debug", False),
            ("Déchiffre les volumes", False),
        ],
        1,
        explanation="-d libère le terminal : le conteneur tourne en fond.",
    )
    add_tf(
        l3,
        "Sans -p, un service web dans le conteneur n'est pas accessible depuis l'hôte.",
        True,
        2,
        explanation="Le mapping de ports est nécessaire pour accéder depuis l'extérieur du conteneur.",
    )
    add_fill(
        l3,
        "Pour voir les logs d'un conteneur : docker ??? <nom>",
        "logs",
        3,
        explanation="docker logs -f suit les logs en temps réel (comme tail -f).",
    )

    l4 = create_lesson(
        u2,
        "Volumes et persistance",
        "Garder ses données quand le conteneur est supprimé",
        2,
        35,
    )
    add_mc(
        l4,
        "Sans volume, les données d'une base dans un conteneur :",
        [
            ("Peuvent disparaître si on supprime le conteneur", True),
            ("Sont toujours sauvegardées sur GitHub", False),
            ("Sont automatiquement dans le cloud", False),
            ("Ne peuvent pas être écrites", False),
        ],
        0,
        explanation="Le filesystem du conteneur est éphémère. Les volumes persistent sur l'hôte.",
    )
    add_mc(
        l4,
        "Quelle option monte un volume nommé « data » vers /var/lib/mysql ?",
        [
            ("-v data:/var/lib/mysql", True),
            ("-p data:mysql", False),
            ("-m data", False),
            ("--copy data", False),
        ],
        1,
        hint="-v source:destination",
        explanation="-v lie un volume (ou chemin hôte) à un chemin dans le conteneur.",
    )
    add_tf(
        l4,
        "Un volume Docker survit à la suppression du conteneur qui l'utilisait.",
        True,
        2,
        explanation="C'est le mécanisme standard pour persister BDD, fichiers uploadés, etc.",
    )
    add_mc(
        l4,
        "docker exec -it mon_conteneur bash permet de :",
        [
            ("Ouvrir un shell interactif dans un conteneur en cours", True),
            ("Supprimer le conteneur", False),
            ("Créer une nouvelle image", False),
            ("Compiler le noyau Linux", False),
        ],
        3,
        explanation="exec = exécuter une commande dans un conteneur déjà lancé. -it = interactif + TTY.",
    )

    u3 = create_unit(
        track,
        "Étape 3 — Créer ses propres images",
        "Le Dockerfile : votre recette personnalisée",
        3,
    )

    l5 = create_lesson(
        u3,
        "Anatomie d'un Dockerfile",
        "Chaque instruction ajoute une couche à l'image",
        1,
        35,
    )
    add_mc(
        l5,
        "Quelle instruction Dockerfile définit l'image de base ?",
        [
            ("FROM python:3.12", True),
            ("BASE python", False),
            ("START python", False),
            ("USE python", False),
        ],
        0,
        explanation="FROM doit être la première instruction (sauf ARG). Elle fixe l'OS/runtime de base.",
    )
    add_mc(
        l5,
        "COPY app.py /app/ dans un Dockerfile :",
        [
            ("Copie app.py de l'hôte vers /app/ dans l'image", True),
            ("Télécharge app.py depuis Internet", False),
            ("Supprime app.py", False),
            ("Compile app.py", False),
        ],
        1,
        explanation="COPY et ADD intègrent des fichiers locaux dans l'image au build.",
    )
    add_fill(
        l5,
        "Quelle instruction définit la commande par défaut au démarrage ? (???)",
        "cmd",
        2,
        hint="3 lettres, en majuscules dans le Dockerfile",
        explanation="CMD [\"python\", \"app.py\"] — peut être surchargé par docker run.",
    )
    add_tf(
        l5,
        "Chaque instruction Dockerfile crée une nouvelle couche (layer) mise en cache.",
        True,
        3,
        explanation="Le cache accélère les rebuilds si les couches n'ont pas changé.",
    )

    l6 = create_lesson(
        u3,
        "Docker Compose — Orchestrer plusieurs services",
        "Un fichier YAML pour lancer app + base de données ensemble",
        2,
        40,
    )
    add_mc(
        l6,
        "docker-compose.yml sert à :",
        [
            ("Définir et lancer plusieurs conteneurs liés (app, db, cache…)", True),
            ("Remplacer Git", False),
            ("Compiler du C++", False),
            ("Configurer le BIOS", False),
        ],
        0,
        explanation="Compose décrit les services, réseaux et volumes dans un seul fichier déclaratif.",
    )
    add_mc(
        l6,
        "Quelle commande démarre tous les services définis dans compose ?",
        [
            ("docker compose up -d", True),
            ("docker start all", False),
            ("compose run", False),
            ("docker build compose", False),
        ],
        1,
        hint="up = démarrer la stack",
        explanation="docker compose up -d lance toute la stack en arrière-plan.",
    )
    add_tf(
        l6,
        "Dans Compose, un service « db » peut être joint par le nom d'hôte « db » par l'app.",
        True,
        2,
        explanation="Compose crée un réseau interne : les services se résolvent par leur nom.",
    )
    add_fill(
        l6,
        "Pour construire les images avant de lancer : docker compose ???",
        "build",
        3,
        explanation="docker compose build reconstruit les images. up --build fait les deux.",
    )


def load_reseaux_avances():
    """Parcours 10 — Réseaux avancés, expliqués avec des schémas mentaux simples."""
    track = create_track(
        "Réseaux Avancés",
        "reseaux-avances",
        "Routage, VLAN, VPN et pare-feu — pour aller plus loin après les bases TCP/IP, "
        "toujours avec des explications pas à pas.",
        "📡",
        "#2C3E50",
        10,
    )

    u1 = create_unit(
        track,
        "Étape 1 — Routage IP",
        "Comment un paquet choisit son chemin sur Internet",
        1,
    )

    l1 = create_lesson(
        u1,
        "La table de routage",
        "Chaque routeur consulte une table pour décider où envoyer le paquet suivant",
        1,
        35,
    )
    add_mc(
        l1,
        "Un routeur reçoit un paquet destiné à 203.0.113.50. Il consulte :",
        [
            ("Sa table de routage", True),
            ("Son agenda Outlook", False),
            ("Le registre DNS du PC", False),
            ("La mémoire RAM du serveur web", False),
        ],
        0,
        hint="Où envoyer ce paquet ? → table de routage",
        explanation="La table indique : « pour ce réseau → envoyer vers telle interface/passerelle ».",
    )
    add_mc(
        l1,
        "La passerelle par défaut (default gateway) sert à :",
        [
            ("Envoyer les paquets dont la destination n'est pas sur le réseau local", True),
            ("Stocker les emails", False),
            ("Chiffrer le Wi-Fi", False),
            ("Attribuer des adresses MAC", False),
        ],
        1,
        explanation="Si la destination n'est pas locale, le paquet part vers la gateway (souvent la box).",
    )
    add_tf(
        l1,
        "Un routeur peut connecter plusieurs réseaux IP différents entre eux.",
        True,
        2,
        explanation="C'est sa fonction : relier des réseaux et router entre eux.",
    )
    add_mc(
        l1,
        "Quelle commande Windows/Linux affiche la table de routage locale ?",
        [
            ("route print (Win) / ip route (Linux)", True),
            ("ping", False),
            ("format c:", False),
            ("ls -la", False),
        ],
        3,
        hint="route ou ip route",
        explanation="Voir la table aide au diagnostic : quelle gateway, quels réseaux locaux.",
    )

    l2 = create_lesson(
        u1,
        "Sous-réseaux en pratique",
        "Découper 192.168.1.0/24 en plusieurs petits réseaux",
        2,
        35,
    )
    add_mc(
        l2,
        "Un réseau 192.168.10.0/26 contient combien d'adresses au total ?",
        [
            ("64", True),
            ("256", False),
            ("32", False),
            ("128", False),
        ],
        0,
        hint="/26 = 32-26 = 6 bits hôtes → 2^6 = 64",
        explanation="/26 laisse 6 bits pour les hôtes : 2⁶ = 64 adresses (62 utilisables en pratique).",
    )
    add_tf(
        l2,
        "Deux machines sur le même sous-réseau peuvent communiquer sans passer par un routeur.",
        True,
        1,
        explanation="Même réseau = communication directe (couche 2/L3 locale).",
    )
    add_mc(
        l2,
        "Le masque 255.255.255.192 équivaut au CIDR :",
        [
            ("/26", True),
            ("/24", False),
            ("/16", False),
            ("/8", False),
        ],
        2,
        hint="192 = 11000000 → 26 bits réseau",
        explanation="255.255.255.192 = /26 (26 bits à 1 dans le masque).",
    )
    add_fill(
        l2,
        "L'adresse réseau (non assignable à un hôte) est souvent la première du sous-réseau ; "
        "la dernière est le ???cast",
        "broad",
        3,
        hint="Broad… — envoi à tous les hôtes du réseau",
        explanation="Broadcast = dernier de la plage. Ni réseau ni broadcast ne sont assignés aux hôtes.",
    )

    u2 = create_unit(
        track,
        "Étape 2 — VLAN et segmentation",
        "Séparer logiquement un même switch physique",
        2,
    )

    l3 = create_lesson(
        u2,
        "Comprendre les VLAN",
        "Un VLAN = un réseau local virtuel, indépendant du câblage physique",
        1,
        35,
    )
    add_mc(
        l3,
        "Un VLAN permet de :",
        [
            ("Séparer le trafic (ex: comptabilité / invités) sur le même switch", True),
            ("Augmenter la vitesse du processeur", False),
            ("Remplacer le DNS", False),
            ("Chiffrer HTTPS", False),
        ],
        0,
        explanation="Séparation logique = sécurité et organisation sans câbles supplémentaires.",
    )
    add_mc(
        l3,
        "Le standard de étiquetage VLAN sur les trunks Ethernet est :",
        [
            ("802.1Q", True),
            ("802.11", False),
            ("HTTP/2", False),
            ("TLS 1.3", False),
        ],
        1,
        hint="802.1… — le Q est la bonne lettre",
        explanation="802.1Q ajoute un tag VLAN aux trames sur les liens trunk entre switches.",
    )
    add_tf(
        l3,
        "Sans routeur (ou L3 switch), deux VLAN différents ne communiquent pas entre eux.",
        True,
        2,
        explanation="Le routage inter-VLAN se fait au niveau 3 (routeur ou switch L3).",
    )
    add_mc(
        l3,
        "Un port « access » sur un switch est typiquement :",
        [
            ("Connecté à un seul VLAN (poste utilisateur)", True),
            ("Connecté à tous les VLAN sans tag", False),
            ("Désactivé par défaut", False),
            ("Réservé au Wi-Fi", False),
        ],
        3,
        explanation="Access = un VLAN. Trunk = plusieurs VLAN tagués (vers autre switch/routeur).",
    )

    l4 = create_lesson(
        u2,
        "Routage inter-VLAN",
        "Faire dialoguer des VLAN tout en gardant la séparation",
        2,
        35,
    )
    add_tf(
        l4,
        "Le routage inter-VLAN filtre le trafic entre segments pour appliquer des politiques.",
        True,
        0,
        explanation="On peut autoriser VLAN A → serveur, bloquer VLAN invité → LAN interne.",
    )
    add_mc(
        l4,
        "Quel équipement route typiquement entre VLAN sur un réseau d'entreprise ?",
        [
            ("Routeur ou switch de couche 3", True),
            ("Uniquement un hub", False),
            ("Une imprimante", False),
            ("Un câble HDMI", False),
        ],
        1,
        explanation="Switch L3 = switch + routage intégré — courant en entreprise.",
    )
    add_fill(
        l4,
        "Un pare-feu entre VLAN peut appliquer des règles ACL (Access Control ???)",
        "list",
        2,
        hint="Liste de contrôle d'accès",
        explanation="ACL = liste de règles allow/deny par IP, port, protocole.",
    )
    add_mc(
        l4,
        "Le « principe du moindre privilège » en réseau signifie :",
        [
            ("N'accorder que l'accès strictement nécessaire", True),
            ("Tout autoriser par défaut", False),
            ("Désactiver tous les pare-feu", False),
            ("Partager un seul mot de passe", False),
        ],
        3,
        explanation="Chaque VLAN/utilisateur n'accède qu'aux ressources requises — base de la sécurité.",
    )

    u3 = create_unit(
        track,
        "Étape 3 — VPN et pare-feu",
        "Sécuriser les connexions distantes et filtrer le trafic",
        3,
    )

    l5 = create_lesson(
        u3,
        "Les VPN expliqués simplement",
        "Un tunnel chiffré à travers Internet",
        1,
        35,
    )
    add_mc(
        l5,
        "Un VPN (Virtual Private Network) crée :",
        [
            ("Un tunnel chiffré pour relier des réseaux ou un utilisateur distant", True),
            ("Un virus sur le réseau", False),
            ("Un nouveau processeur", False),
            ("Une adresse MAC aléatoire", False),
        ],
        0,
        explanation="Le VPN encapsule et chiffre le trafic : sécurité sur un réseau non fiable (Internet).",
    )
    add_mc(
        l5,
        "Un VPN « site-to-site » relie :",
        [
            ("Deux sites/bureaux entre eux", True),
            ("Un utilisateur à son clavier", False),
            ("Deux disques durs", False),
            ("Un switch à une imprimante USB", False),
        ],
        1,
        hint="Site = lieu physique (bureau, datacenter)",
        explanation="Site-to-site = tunnel permanent entre deux réseaux d'entreprise.",
    )
    add_tf(
        l5,
        "Un VPN remote access permet à un télétravailleur d'accéder au réseau interne.",
        True,
        2,
        explanation="Le client VPN sur le laptop crée un tunnel vers le siège.",
    )
    add_fill(
        l5,
        "Le protocole VPN souvent utilisé avec IPsec ou OpenVPN chiffre la couche ???",
        "3",
        3,
        hint="Couche réseau du modèle OSI",
        explanation="IPsec opère en couche 3. SSL VPN (OpenVPN) peut utiliser TLS (couche plus haute).",
    )

    l6 = create_lesson(
        u3,
        "Pare-feu et NAT",
        "Filtrer ce qui entre et sort ; partager une IP publique",
        2,
        35,
    )
    add_mc(
        l6,
        "Un pare-feu stateful inspecte :",
        [
            ("Les connexions et leur état (établie, nouvelle…)", True),
            ("Uniquement la couleur des câbles", False),
            ("Le modèle du PC", False),
            ("La version de Python", False),
        ],
        0,
        explanation="Stateful = mémorise les connexions légitimes pour laisser passer les réponses.",
    )
    add_mc(
        l6,
        "Le NAT (Network Address Translation) permet à plusieurs machines d'utiliser :",
        [
            ("Une seule adresse IP publique", True),
            ("Des millions d'IP publiques chacune", False),
            ("Aucune IP", False),
            ("Uniquement IPv6", False),
        ],
        1,
        explanation="La box traduit IP privées (192.168.x.x) vers l'IP publique du FAI.",
    )
    add_tf(
        l6,
        "Une règle pare-feu « DENY all » par défaut est une bonne pratique de sécurité.",
        True,
        2,
        explanation="Default deny : tout est bloqué sauf ce qu'on autorise explicitement (whitelist).",
    )
    add_mc(
        l6,
        "Le PAT (Port Address Translation) est aussi appelé :",
        [
            ("NAT overload / NAT avec ports", True),
            ("DNS inverse", False),
            ("DHCP statique", False),
            ("ARP gratuit", False),
        ],
        3,
        hint="Plusieurs connexions partagent la même IP via des ports différents",
        explanation="PAT = plusieurs sessions internes mappées sur des ports de l'IP publique.",
    )

    u4 = create_unit(
        track,
        "Étape 4 — Diagnostiquer un réseau",
        "Méthode pas à pas quand « ça ne ping pas »",
        4,
    )

    l7 = create_lesson(
        u4,
        "Les outils du diagnostic",
        "ping, traceroute, nslookup — dans quel ordre les utiliser",
        1,
        35,
    )
    add_mc(
        l7,
        "ping 8.8.8.8 teste principalement :",
        [
            ("La connectivité IP vers cette adresse", True),
            ("La vitesse de votre disque dur", False),
            ("La validité de votre mot de passe", False),
            ("La version de votre navigateur", False),
        ],
        0,
        explanation="ping = ICMP echo. Pas de réponse → problème couche 3, firewall, ou cible down.",
    )
    add_mc(
        l7,
        "traceroute (ou tracert) montre :",
        [
            ("Chaque saut (routeur) jusqu'à la destination", True),
            ("Le mot de passe Wi-Fi", False),
            ("La température CPU", False),
            ("Les fichiers ouverts", False),
        ],
        1,
        explanation="Utile pour voir où le paquet s'arrête (quel routeur ne répond plus).",
    )
    add_tf(
        l7,
        "Si ping IP fonctionne mais pas ping par nom, le problème est probablement DNS.",
        True,
        2,
        explanation="IP OK mais nom échoue → résolution DNS à vérifier (nslookup, dig).",
    )
    add_fill(
        l7,
        "Pour tester la résolution de noms : nslookup ou ???",
        "dig",
        3,
        hint="Outil Linux courant, 3 lettres",
        explanation="nslookup et dig interrogent les serveurs DNS.",
    )

    l8 = create_lesson(
        u4,
        "Méthodologie de dépannage",
        "Couche par couche, du physique à l'application",
        2,
        40,
    )
    add_mc(
        l8,
        "Quelle est la bonne première étape de dépannage réseau ?",
        [
            ("Vérifier câble/Wi-Fi connecté et IP obtenue (ipconfig/ifconfig)", True),
            ("Réinstaller Windows immédiatement", False),
            ("Changer tous les mots de passe", False),
            ("Acheter un nouveau switch", False),
        ],
        0,
        explanation="Méthode OSI bottom-up : physique → liaison → réseau → … avant de suspecter l'app.",
    )
    add_mc(
        l8,
        "Le modèle OSI aide au diagnostic car :",
        [
            ("On isole la couche en cause (câble ? IP ? DNS ? App ?)", True),
            ("Il remplace ping", False),
            ("Il configure le DHCP", False),
            ("Il chiffre le trafic", False),
        ],
        1,
        explanation="Couche 1-2 : lien. 3 : IP/routage. 4 : ports TCP. 7 : application HTTP…",
    )
    add_tf(
        l8,
        "Documenter chaque test (ping, traceroute, résultat) accélère la résolution en équipe.",
        True,
        2,
        explanation="Traçabilité = un collègue peut reprendre sans tout refaire.",
    )
    add_mc(
        l8,
        "netstat ou ss permet de voir :",
        [
            ("Les connexions et ports en écoute sur la machine", True),
            ("La météo", False),
            ("Les mises à jour Windows", False),
            ("Le taux de change", False),
        ],
        3,
        hint="Quel service écoute sur le port 80 ?",
        explanation="ss -tlnp (Linux) liste ports TCP en écoute — utile si « service injoignable ».",
    )


# Registre de tous les parcours
CONTENT_LOADERS = [
    load_python_fondamentaux,
    load_reseaux,
    load_cybersecurite,
    load_web_dev,
    load_linux,
    load_bases_de_donnees,
    load_git,
    load_algorithmique,
    load_docker,
    load_reseaux_avances,
]
