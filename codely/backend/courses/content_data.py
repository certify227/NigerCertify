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


# Registre de tous les parcours
CONTENT_LOADERS = [
    load_python_fondamentaux,
    load_reseaux,
    load_cybersecurite,
    load_web_dev,
    load_linux,
    load_bases_de_donnees,
    load_git,
]
