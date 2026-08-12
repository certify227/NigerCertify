"""
Parcours fondamentaux 3 à 7 — version pédagogique enrichie.
Cybersécurité, Web, Linux, BDD SQL et Git.
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


def load_cybersecurite():
    track = create_track(
        "Cybersécurité",
        "cybersecurite",
        "Protégez vos applications comme un gardien de château : "
        "comprendre les attaques (OWASP), le chiffrement et les bonnes pratiques.",
        "🔒",
        "#FF4B4B",
        3,
    )

    u1 = create_unit(
        track,
        "Étape 1 — Les failles web critiques",
        "OWASP Top 10 : les vulnérabilités que chaque développeur doit connaître",
        1,
    )

    l1 = create_lesson(
        u1,
        "Injection SQL — Le pirate dans la requête",
        "Quand un attaquant glisse du code SQL dans un champ de formulaire",
        1,
        35,
    )
    add_tf(
        l1,
        "L'injection SQL exploite des requêtes où le texte utilisateur est concaténé directement.",
        True,
        0,
        hint="Comme glisser une instruction dans une phrase",
        explanation="Si login = ' OR 1=1 --', une requête mal construite peut tout afficher. "
                    "Les requêtes préparées séparent le code SQL des données.",
    )
    add_mc(
        l1,
        "Quelle est la MEILLEURE défense contre l'injection SQL ?",
        [
            ("Échapper les guillemets manuellement", False),
            ("Requêtes préparées (paramétrées)", True),
            ("Cacher la base de données", False),
            ("Utiliser HTTP au lieu de HTTPS", False),
        ],
        1,
        hint="Séparer le « modèle » SQL des « valeurs »",
        explanation="Les ORM et requêtes paramétrées (SELECT * FROM users WHERE id = ?) "
                    "empêchent l'utilisateur de modifier la structure SQL.",
    )
    add_fill(
        l1,
        "En injection SQL, le caractère ??? termine souvent une instruction pour en commencer une autre",
        ";",
        2,
        hint="Point-virgule — comme en Python ou en français",
        explanation="; sépare les instructions SQL. Un attaquant peut injecter ; DROP TABLE users; …",
    )
    add_tf(
        l1,
        "Valider et filtrer les entrées côté SERVEUR est indispensable.",
        True,
        3,
        hint="Le navigateur peut être contourné",
        explanation="Ne jamais faire confiance au client : toute donnée peut être falsifiée. "
                    "Validation serveur = filet de sécurité.",
    )
    add_mc(
        l1,
        "Une requête préparée fonctionne comme :",
        [
            ("Un formulaire papier avec des champs vides à remplir", True),
            ("Un mot de passe en clair dans le code", False),
            ("Une connexion Wi-Fi ouverte", False),
            ("Un fichier sans permissions", False),
        ],
        4,
        hint="Le SQL est fixe, seules les valeurs changent",
        explanation="Analogie : le modèle SQL est imprimé ; les paramètres sont insérés sans altérer le modèle.",
    )

    l2 = create_lesson(
        u1,
        "Cross-Site Scripting (XSS)",
        "Injecter du JavaScript malveillant dans une page vue par d'autres",
        2,
        35,
    )
    add_tf(
        l2,
        "Le XSS permet d'exécuter du script dans le navigateur de la victime.",
        True,
        0,
        hint="Script = code exécutable côté client",
        explanation="XSS = Cross-Site Scripting. Le site « reflète » ou « stocke » du JS malveillant "
                    "qui s'exécute chez l'utilisateur.",
    )
    add_mc(
        l2,
        "Comment prévenir le XSS quand on affiche du contenu utilisateur ?",
        [
            ("Désactiver JavaScript pour tous", False),
            ("Échapper/encoder les sorties HTML (<, >, &)", True),
            ("Utiliser HTTP non chiffré", False),
            ("Supprimer tous les cookies", False),
        ],
        1,
        hint="Transformer <script> en texte inoffensif",
        explanation="Encoder < en &lt; empêche le navigateur d'interpréter une balise script.",
    )
    add_tf(
        l2,
        "Content-Security-Policy (CSP) limite les sources de scripts autorisées.",
        True,
        2,
        hint="Liste blanche de domaines pour les scripts",
        explanation="CSP dit au navigateur : « n'exécute les scripts que depuis ces URLs » — "
                    "mitige le XSS même si une faille existe.",
    )
    add_mc(
        l2,
        "Le XSS « réfléchi » place le payload :",
        [
            ("Dans la base de données pour toujours", False),
            ("Dans l'URL ou la requête, renvoyé immédiatement", True),
            ("Uniquement dans les cookies HttpOnly", False),
            ("Dans le certificat TLS", False),
        ],
        3,
        hint="Comme un miroir : ce que vous envoyez revient dans la page",
        explanation="XSS réfléchi : ?search=<script>…</script> — la page affiche la recherche sans filtrer.",
    )
    add_mc(
        l2,
        "Le XSS « stocké » est particulièrement dangereux car :",
        [
            ("Il ne nécessite pas JavaScript", False),
            ("Le script malveillant persiste et frappe chaque visiteur", True),
            ("Il chiffre les données", False),
            ("Il ne touche que le serveur", False),
        ],
        4,
        hint="Commentaire de forum, profil utilisateur…",
        explanation="Stocké = en BDD. Chaque lecteur exécute le script — attaque à grande échelle.",
    )

    l3 = create_lesson(
        u1,
        "CSRF et authentification",
        "Forcer un utilisateur connecté à agir sans son consentement",
        3,
        35,
    )
    add_tf(
        l3,
        "CSRF force un utilisateur authentifié à exécuter une action non voulue.",
        True,
        0,
        hint="Cross-Site Request Forgery",
        explanation="Exemple : vous êtes connecté à votre banque ; un site malveillant envoie "
                    "un formulaire caché qui transfère de l'argent.",
    )
    add_mc(
        l3,
        "Quel mécanisme protège typiquement contre le CSRF ?",
        [
            ("JWT access token seul", False),
            ("Token CSRF synchronisé dans le formulaire", True),
            ("Cookie de session sans attributs", False),
            ("L'adresse IP du client", False),
        ],
        1,
        hint="Secret connu seulement par votre site et le formulaire légitime",
        explanation="Le serveur génère un token ; le formulaire doit le renvoyer — "
                    "un site externe ne peut pas le deviner.",
    )
    add_mc(
        l3,
        "Quel attribut cookie limite l'envoi cross-site ?",
        [
            ("HttpOnly", False),
            ("SameSite", True),
            ("Secure", False),
            ("Domain", False),
        ],
        2,
        hint="Same = même site",
        explanation="SameSite=Strict/Lax empêche le navigateur d'envoyer le cookie "
                    "depuis un autre domaine — barrière CSRF.",
    )
    add_tf(
        l3,
        "MFA (authentification multi-facteurs) renforce la sécurité des comptes.",
        True,
        3,
        hint="Mot de passe + autre chose",
        explanation="MFA = mot de passe + TOTP/SMS/biométrie. Même si le mot de passe fuite, "
                    "l'attaquant est bloqué.",
    )
    add_mc(
        l3,
        "HttpOnly sur un cookie empêche :",
        [
            ("JavaScript d'accéder au cookie", True),
            ("Le serveur de lire le cookie", False),
            ("HTTPS de chiffrer le cookie", False),
            ("Le cookie d'expirer", False),
        ],
        4,
        hint="Protection contre le vol via XSS",
        explanation="HttpOnly : seul le navigateur envoie le cookie au serveur — "
                    "document.cookie ne peut pas le lire.",
    )

    u2 = create_unit(
        track,
        "Étape 2 — Cryptographie & HTTPS",
        "Hasher, chiffrer et établir la confiance sur le web",
        2,
    )

    l4 = create_lesson(
        u2,
        "Hash vs Chiffrement",
        "Intégrité (empreinte) vs confidentialité (secret)",
        1,
        35,
    )
    add_mc(
        l4,
        "Une fonction de hachage (hash) est-elle réversible ?",
        [
            ("Oui, toujours", False),
            ("Non, c'est à sens unique", True),
            ("Oui, avec la clé privée", False),
            ("Non, sauf pour MD5", False),
        ],
        0,
        hint="Empreinte digitale — on ne reconstruit pas la personne",
        explanation="Hash = empreinte. bcrypt('secret') → $2b$… impossible à « déhasher ». "
                    "On compare en re-hashant.",
    )
    add_mc(
        l4,
        "Quel algorithme est recommandé pour stocker des mots de passe ?",
        [
            ("MD5", False),
            ("SHA-1", False),
            ("bcrypt ou Argon2", True),
            ("Base64", False),
        ],
        1,
        hint="Volontairement lent pour décourager le brute-force",
        explanation="bcrypt/Argon2 sont lents et salés — chaque mot de passe a un grain de sel unique.",
    )
    add_tf(
        l4,
        "AES est un algorithme de chiffrement symétrique (une seule clé).",
        True,
        2,
        hint="Symétrique = même clé pour chiffrer et déchiffrer",
        explanation="AES chiffre avec une clé secrète partagée. RSA utilise une paire clé publique/privée.",
    )
    add_fill(
        l4,
        "Le protocole qui sécurise HTTP avec TLS s'appelle ???",
        "https",
        3,
        hint="HTTP + S pour Secure",
        explanation="HTTPS = HTTP chiffré par TLS. Le cadenas dans le navigateur = connexion HTTPS.",
    )
    add_mc(
        l4,
        "Base64 est :",
        [
            ("Un encodage, pas un chiffrement sécurisé", True),
            ("Un algorithme de hash militaire", False),
            ("Un certificat TLS", False),
            ("Un firewall", False),
        ],
        4,
        hint="Tout le monde peut décoder Base64",
        explanation="Base64 transforme des bytes en texte ASCII — pas secret du tout. "
                    "Ne jamais l'utiliser pour « cacher » des mots de passe.",
    )

    l5 = create_lesson(
        u2,
        "Certificats TLS et confiance",
        "Comment le navigateur vérifie que le site est le bon",
        2,
        35,
    )
    add_mc(
        l5,
        "Qui émet les certificats TLS de confiance pour les sites web ?",
        [
            ("L'utilisateur final", False),
            ("Autorité de Certification (CA)", True),
            ("Le routeur Wi-Fi", False),
            ("Le registre DNS", False),
        ],
        0,
        hint="Certificate Authority",
        explanation="Les CA (Let's Encrypt, DigiCert…) signent les certificats. "
                    "Le navigateur vérifie la chaîne de confiance.",
    )
    add_tf(
        l5,
        "Un certificat auto-signé provoque un avertissement dans le navigateur.",
        True,
        1,
        hint="Personne d'externe n'a validé l'identité",
        explanation="Auto-signé = OK en dev local, mais pas de CA reconnue → alerte sécurité en production.",
    )
    add_mc(
        l5,
        "En TLS, les données sont chiffrées avec :",
        [
            ("La clé publique du serveur pour tout le trafic", False),
            ("Une clé de session symétrique (après échange sécurisé)", True),
            ("Le hash SHA-256 seul", False),
            ("Le mot de passe utilisateur", False),
        ],
        2,
        hint="Échange hybride : RSA/ECDHE puis AES rapide",
        explanation="TLS négocie une clé de session symétrique — AES est rapide pour des gros volumes.",
    )
    add_tf(
        l5,
        "TLS protège la confidentialité et l'intégrité des données en transit.",
        True,
        3,
        hint="Personne sur le réseau ne peut lire ni modifier silencieusement",
        explanation="Sans TLS, un attaquant sur le Wi-Fi peut lire les mots de passe en clair.",
    )
    add_mc(
        l5,
        "Le cadenas HTTPS dans la barre d'adresse signifie :",
        [
            ("Le site est 100 % sans failles", False),
            ("La connexion entre vous et le serveur est chiffrée", True),
            ("Le site ne utilise pas JavaScript", False),
            ("Vos données sont sauvegardées localement", False),
        ],
        4,
        hint="Chiffrement du canal, pas audit de sécurité complet",
        explanation="HTTPS chiffre le transport. Le site peut encore avoir des bugs XSS ou SQL — "
                    "deux couches de sécurité différentes.",
    )


def load_web_dev():
    track = create_track(
        "Développement Web",
        "developpement-web",
        "Construisez des pages web comme une maison : HTML = murs, CSS = déco, "
        "JavaScript = électricité interactive.",
        "🌍",
        "#CE82FF",
        4,
    )

    u1 = create_unit(
        track,
        "Étape 1 — HTML & CSS",
        "Structure sémantique et mise en forme des pages",
        1,
    )

    l1 = create_lesson(
        u1,
        "Structure HTML — Les balises essentielles",
        "HTML décrit le CONTENU : titres, paragraphes, liens, images",
        1,
        30,
    )
    add_mc(
        l1,
        "Quelle balise contient le contenu visible de la page ?",
        [
            ("<head>", False),
            ("<body>", True),
            ("<meta>", False),
            ("<link>", False),
        ],
        0,
        hint="Ce que l'utilisateur voit dans le navigateur",
        explanation="<head> = métadonnées (titre, CSS). <body> = tout le contenu affiché.",
    )
    add_mc(
        l1,
        "Quelle balise crée un lien cliquable vers une autre page ?",
        [
            ("<link>", False),
            ("<a>", True),
            ("<href>", False),
            ("<url>", False),
        ],
        1,
        hint="Anchor = ancre, lien",
        explanation="<a href='https://…'>Texte</a> — href = hypertext reference.",
    )
    add_fill(
        l1,
        "Quelle balise insère une image ? (??? avec src et alt)",
        "img",
        2,
        hint="3 lettres, pas <image>",
        explanation="<img src='photo.jpg' alt='Description'> — alt est vital pour l'accessibilité.",
    )
    add_tf(
        l1,
        "HTML5 est la version moderne du langage HTML avec balises sémantiques.",
        True,
        3,
        hint="<header>, <nav>, <article>…",
        explanation="HTML5 apporte <section>, APIs (canvas, géolocalisation) et une sémantique claire.",
    )
    add_mc(
        l1,
        "Quelle balise crée un titre de niveau 1 (le plus important) ?",
        [
            ("<title>", False),
            ("<h1>", True),
            ("<header>", False),
            ("<head>", False),
        ],
        4,
        hint="h = heading, 1 = premier niveau",
        explanation="<h1> un seul par page idéalement. <h2>, <h3> pour sous-titres.",
    )

    l2 = create_lesson(
        u1,
        "CSS — Mettre en forme la page",
        "Couleurs, marges, flexbox : le décor de votre site",
        2,
        30,
    )
    add_mc(
        l2,
        "Que signifie CSS ?",
        [
            ("Computer Style Sheets", False),
            ("Cascading Style Sheets", True),
            ("Creative Style System", False),
            ("Color Style Syntax", False),
        ],
        0,
        hint="Feuilles de style en cascade",
        explanation="CSS = Cascading Style Sheets. « Cascade » = les règles se combinent et peuvent s'hériter.",
    )
    add_mc(
        l2,
        "Quel sélecteur CSS cible un élément par son id unique ?",
        [
            (".monId", False),
            ("#monId", True),
            ("*monId", False),
            ("@monId", False),
        ],
        1,
        hint="Point = classe, hash = id",
        explanation="#header { … } cible id='header'. .btn cible class='btn'.",
    )
    add_tf(
        l2,
        "display: flex facilite les mises en page alignées et flexibles.",
        True,
        2,
        hint="Flexbox = rangées et colonnes sans calculs compliqués",
        explanation="Flex aligne, distribue l'espace et réorganise sur mobile — standard du layout moderne.",
    )
    add_fill(
        l2,
        "Quelle propriété CSS change la couleur du texte ? (???)",
        "color",
        3,
        hint="Pas background-color — celle du fond",
        explanation="color: #333; pour le texte. background-color pour le fond.",
    )
    add_mc(
        l2,
        "Quelle unité CSS est relative à la taille de police de l'élément parent ?",
        [
            ("px", False),
            ("em", True),
            ("cm", False),
            ("vh", False),
        ],
        4,
        hint="1em = taille de police courante",
        explanation="em et rem (root em) permettent des designs qui s'adaptent à la taille du texte.",
    )

    u2 = create_unit(
        track,
        "Étape 2 — JavaScript",
        "Rendre la page interactive : clics, formulaires, animations",
        2,
    )

    l3 = create_lesson(
        u2,
        "JavaScript — Variables et fonctions",
        "Le langage qui fait bouger le web dans le navigateur",
        1,
        30,
    )
    add_mc(
        l3,
        "Quel mot-clé déclare une constante en JavaScript moderne ?",
        [
            ("var", False),
            ("const", True),
            ("static", False),
            ("define", False),
        ],
        0,
        hint="const = ne peut pas être réassignée",
        explanation="const pour les constantes, let pour les variables. var est l'ancien style — évitez-le.",
    )
    add_mc(
        l3,
        "Comment écrit-on une fonction fléchée (arrow function) ?",
        [
            ("function => ()", False),
            ("() => {}", True),
            ("def () {}", False),
            ("fn () ->", False),
        ],
        1,
        hint="Parenthèses, flèche, accolades",
        explanation="const double = (x) => x * 2; — syntaxe concise et moderne.",
    )
    add_tf(
        l3,
        "JavaScript s'exécute dans le navigateur et aussi sur le serveur (Node.js).",
        True,
        2,
        hint="Un langage, plusieurs environnements",
        explanation="JS côté client (DOM) et côté serveur (API Node) — très polyvalent.",
    )
    add_mc(
        l3,
        "Quelle méthode sélectionne un élément HTML par son id ?",
        [
            ("document.query()", False),
            ("document.getElementById()", True),
            ("document.find()", False),
            ("window.select()", False),
        ],
        3,
        hint="getElementById('monId')",
        explanation="getElementById retourne un élément. querySelector('#monId') est une alternative moderne.",
    )
    add_code(
        l3,
        "Affichez 2 + 3 en JavaScript (uniquement le nombre)",
        "console.log(2 + 3)",
        "5",
        4,
        hint="console.log() affiche dans la console du navigateur",
        explanation="console.log(2 + 3) affiche 5 — premier pas en JS !",
    )

    l4 = create_lesson(
        u2,
        "DOM et événements",
        "Réagir aux clics, saisies et chargement de la page",
        2,
        35,
    )
    add_mc(
        l4,
        "Que signifie DOM ?",
        [
            ("Data Object Model", False),
            ("Document Object Model", True),
            ("Dynamic Output Method", False),
            ("Document Oriented Markup", False),
        ],
        0,
        hint="La page HTML vue comme un arbre d'objets",
        explanation="DOM = représentation objet de la page. JavaScript peut lire et modifier chaque nœud.",
    )
    add_tf(
        l4,
        "addEventListener('click', handler) écoute les clics sur un élément.",
        True,
        1,
        hint="Événement + fonction callback",
        explanation="btn.addEventListener('click', () => alert('Clic !')); — pattern fondamental.",
    )
    add_fill(
        l4,
        "Pour empêcher le rechargement d'un formulaire : event.prevent???()",
        "preventdefault",
        2,
        hint="preventDefault — annule l'action par défaut",
        explanation="Sans preventDefault(), le formulaire recharge la page — bloquant pour les apps AJAX.",
    )
    add_mc(
        l4,
        "Quel événement indique que le DOM est prêt à manipuler ?",
        [
            ("onhover", False),
            ("DOMContentLoaded", True),
            ("onscroll", False),
            ("onresize", False),
        ],
        3,
        hint="Le HTML est parsé, on peut attacher des listeners",
        explanation="DOMContentLoaded : images pas encore chargées, mais structure DOM disponible.",
    )
    add_mc(
        l4,
        "Pour modifier le texte d'un élément <p id='msg'>, on peut utiliser :",
        [
            ("document.getElementById('msg').textContent = 'Bonjour'", True),
            ("document.msg = 'Bonjour'", False),
            ("HTML.setText('msg', 'Bonjour')", False),
            ("window.write('Bonjour')", False),
        ],
        4,
        hint="Propriété textContent ou innerHTML",
        explanation="textContent = texte brut. innerHTML interprète le HTML — attention au XSS !",
    )


def load_linux():
    track = create_track(
        "Linux & Systèmes",
        "linux-systemes",
        "Le terminal Linux, c'est le cockpit du développeur : naviguer, gérer les fichiers "
        "et les permissions comme un admin.",
        "🐧",
        "#FCC624",
        5,
    )

    u1 = create_unit(
        track,
        "Étape 1 — Commandes essentielles",
        "Naviguer et manipuler fichiers et dossiers en ligne de commande",
        1,
    )

    l1 = create_lesson(
        u1,
        "Navigation — Où suis-je ?",
        "pwd, ls, cd : votre GPS dans l'arborescence Linux",
        1,
        30,
    )
    add_mc(
        l1,
        "Quelle commande affiche le répertoire courant (où vous êtes) ?",
        [
            ("ls", False),
            ("pwd", True),
            ("cd", False),
            ("dir", False),
        ],
        0,
        hint="Print Working Directory",
        explanation="pwd affiche /home/user/projets — votre position dans l'arborescence.",
    )
    add_mc(
        l1,
        "Quelle commande liste les fichiers d'un répertoire ?",
        [
            ("list", False),
            ("ls", True),
            ("show", False),
            ("cat", False),
        ],
        1,
        hint="List — comme une table des matières",
        explanation="ls liste le contenu. ls -la montre aussi les fichiers cachés et les permissions.",
    )
    add_fill(
        l1,
        "Quelle commande change de répertoire ? (??)",
        "cd",
        2,
        hint="Change Directory — 2 lettres",
        explanation="cd /var/log ou cd .. (parent) ou cd ~ (maison).",
    )
    add_tf(
        l1,
        "cd .. remonte au répertoire parent (un niveau au-dessus).",
        True,
        3,
        hint=".. = dossier parent, . = dossier courant",
        explanation=". = ici, .. = parent. cd ../.. remonte deux niveaux.",
    )
    add_mc(
        l1,
        "La commande ls -l affiche :",
        [
            ("Uniquement les noms de fichiers", False),
            ("Permissions, propriétaire, taille et date", True),
            ("Le contenu texte des fichiers", False),
            ("L'adresse IP", False),
        ],
        4,
        hint="-l = long format",
        explanation="ls -l : -rw-r--r-- 1 user group 4096 Jan 1 fichier.txt — très informatif.",
    )

    l2 = create_lesson(
        u1,
        "Fichiers et dossiers — Créer, copier, supprimer",
        "mkdir, touch, cp, rm : les outils du quotidien",
        2,
        30,
    )
    add_mc(
        l2,
        "Quelle commande crée un nouveau répertoire ?",
        [
            ("mkdir", True),
            ("touch", False),
            ("mkfile", False),
            ("newdir", False),
        ],
        0,
        hint="Make Directory",
        explanation="mkdir mon_dossier crée le dossier. mkdir -p crée aussi les parents manquants.",
    )
    add_mc(
        l2,
        "Quelle commande affiche le contenu d'un fichier texte dans le terminal ?",
        [
            ("show", False),
            ("cat", True),
            ("type", False),
            ("read", False),
        ],
        1,
        hint="Concatenate — comme lire à voix haute",
        explanation="cat fichier.txt affiche tout. head/tail pour le début ou la fin.",
    )
    add_tf(
        l2,
        "rm -rf supprime récursivement sans demander confirmation — TRÈS dangereux.",
        True,
        2,
        hint="-r = récursif, -f = force",
        explanation="rm -rf / par erreur = catastrophe. Toujours vérifier le chemin avant rm -rf.",
    )
    add_mc(
        l2,
        "Quelle commande copie un fichier ?",
        [
            ("mv", False),
            ("cp", True),
            ("copy", False),
            ("scp uniquement", False),
        ],
        3,
        hint="Copy — mv déplace, cp copie",
        explanation="cp source destination. cp -r pour copier un dossier entier.",
    )
    add_mc(
        l2,
        "touch fichier.txt :",
        [
            ("Crée un fichier vide ou met à jour sa date de modification", True),
            ("Supprime le fichier", False),
            ("Chiffre le fichier", False),
            ("Compile le fichier", False),
        ],
        4,
        hint="Utile pour créer rapidement un fichier vide",
        explanation="touch crée si absent, ou met à jour le timestamp — pratique en scripts.",
    )

    u2 = create_unit(
        track,
        "Étape 2 — Permissions & utilisateurs",
        "Qui peut lire, écrire ou exécuter quoi sur le système",
        2,
    )

    l3 = create_lesson(
        u2,
        "Permissions Unix — rwx",
        "Trois droits pour trois catégories : propriétaire, groupe, autres",
        1,
        35,
    )
    add_mc(
        l3,
        "Que signifie rwx ?",
        [
            ("read, write, execute", True),
            ("root, write, exit", False),
            ("run, wait, exit", False),
            ("read, wait, export", False),
        ],
        0,
        hint="Lire, écrire, exécuter",
        explanation="r = lire le fichier, w = modifier, x = exécuter (script ou programme).",
    )
    add_mc(
        l3,
        "chmod 755 : quels droits a le propriétaire (premier chiffre 7) ?",
        [
            ("r-x", False),
            ("rwx", True),
            ("rw-", False),
            ("---", False),
        ],
        1,
        hint="7 = 4+2+1 = r+w+x",
        explanation="7=rwx, 5=r-x, 5=r-x. Propriétaire tout, groupe et autres : lire et exécuter.",
    )
    add_tf(
        l3,
        "Le superutilisateur Linux s'appelle root (UID 0).",
        True,
        2,
        hint="Tous les privilèges — à utiliser avec prudence",
        explanation="root peut tout faire. sudo permet d'exécuter une commande en root temporairement.",
    )
    add_fill(
        l3,
        "Quelle commande change le propriétaire d'un fichier ? (ch???)",
        "chown",
        3,
        hint="Change Owner",
        explanation="chown user:group fichier. Souvent utilisé après copie de fichiers.",
    )
    add_mc(
        l3,
        "Un script shell doit avoir le droit :",
        [
            ("x (exécution) pour être lancé avec ./script.sh", True),
            ("w seul", False),
            ("r seul", False),
            ("Aucun droit", False),
        ],
        4,
        hint="./monscript.sh nécessite x",
        explanation="Sans x, vous pouvez lire le script (cat) mais pas l'exécuter directement.",
    )

    l4 = create_lesson(
        u2,
        "Processus et recherche",
        "Voir ce qui tourne et trouver du texte dans des fichiers",
        2,
        30,
    )
    add_mc(
        l4,
        "Quelle commande affiche les processus en cours ?",
        [
            ("ls", False),
            ("ps aux", True),
            ("cat", False),
            ("pwd", False),
        ],
        0,
        hint="Process Status",
        explanation="ps aux liste tous les processus. top ou htop pour un affichage interactif.",
    )
    add_tf(
        l4,
        "grep recherche du texte dans des fichiers ou dans la sortie d'une commande.",
        True,
        1,
        hint="Global Regular Expression Print",
        explanation="grep 'erreur' log.txt ou ps aux | grep nginx — filtrer l'information.",
    )
    add_fill(
        l4,
        "Pour chercher « error » dans app.log : ??? error app.log",
        "grep",
        2,
        hint="G rep — chercher un motif",
        explanation="grep -i error app.log ignore la casse. grep -r cherche récursivement dans les dossiers.",
    )
    add_mc(
        l4,
        "kill PID arrête un processus. kill -9 :",
        [
            ("Force l'arrêt immédiat (ne peut pas être ignoré)", True),
            ("Redémarre le processus", False),
            ("Met en pause le processus", False),
            ("Affiche les logs du processus", False),
        ],
        3,
        hint="SIGKILL — dernier recours",
        explanation="kill -9 envoie SIGKILL. Essayez kill PID (SIGTERM) avant — plus propre.",
    )
    add_mc(
        l4,
        "La commande which python3 affiche :",
        [
            ("Le chemin du binaire python3 utilisé", True),
            ("La version de Python installée", False),
            ("Les modules Python installés", False),
            ("Le PID du processus Python", False),
        ],
        4,
        hint="/usr/bin/python3 typiquement",
        explanation="which trouve où est l'exécutable — utile quand plusieurs versions existent.",
    )


def load_bases_de_donnees():
    track = create_track(
        "Bases de données SQL",
        "bases-de-donnees",
        "SQL est le langage pour interroger des tableaux de données — "
        "comme Excel, mais pour des millions de lignes.",
        "🗄️",
        "#FF9600",
        6,
    )

    u1 = create_unit(
        track,
        "Étape 1 — Requêtes SQL fondamentales",
        "SELECT, filtrer, trier et modifier des données",
        1,
    )

    l1 = create_lesson(
        u1,
        "SELECT et WHERE — Lire des données",
        "Interroger une table comme un tableau Excel filtrable",
        1,
        30,
    )
    add_mc(
        l1,
        "Quelle clause SQL filtre les lignes retournées ?",
        [
            ("FILTER", False),
            ("WHERE", True),
            ("HAVING", False),
            ("LIMIT", False),
        ],
        0,
        hint="Où la condition est vraie",
        explanation="SELECT * FROM users WHERE age >= 18 — seules les lignes qui matchent.",
    )
    add_mc(
        l1,
        "SELECT * FROM users récupère :",
        [
            ("Uniquement la colonne id", False),
            ("Toutes les colonnes de la table users", True),
            ("Le nombre de lignes", False),
            ("Les index de la table", False),
        ],
        1,
        hint="* = tout",
        explanation="* = toutes les colonnes. SELECT nom, email FROM users pour choisir.",
    )
    add_fill(
        l1,
        "Pour trier les résultats : ORDER BY colonne ??? ou DESC",
        "asc",
        2,
        hint="Ascending = croissant, DESC = décroissant",
        explanation="ORDER BY prix ASC (du plus petit au plus grand) ou DESC.",
    )
    add_tf(
        l1,
        "SQL est un langage déclaratif : on décrit QUOI on veut, pas COMMENT.",
        True,
        3,
        hint="Le moteur SQL optimise l'exécution",
        explanation="Vous écrivez SELECT … WHERE … ; le SGBD choisit le plan d'exécution optimal.",
    )
    add_mc(
        l1,
        "LIMIT 10 dans une requête :",
        [
            ("Retourne au maximum 10 lignes", True),
            ("Limite à 10 colonnes", False),
            ("Supprime 10 lignes", False),
            ("Crée 10 tables", False),
        ],
        4,
        hint="Utile pour paginer les résultats",
        explanation="LIMIT 10 OFFSET 20 = page 3 avec 10 lignes par page.",
    )

    l2 = create_lesson(
        u1,
        "INSERT, UPDATE, DELETE — Modifier les données",
        "Ajouter, changer ou supprimer des lignes — avec prudence",
        2,
        30,
    )
    add_mc(
        l2,
        "Quelle commande ajoute une nouvelle ligne dans une table ?",
        [
            ("ADD", False),
            ("INSERT INTO", True),
            ("CREATE ROW", False),
            ("APPEND", False),
        ],
        0,
        hint="INSERT INTO table VALUES …",
        explanation="INSERT INTO users (nom, email) VALUES ('Alice', 'a@mail.com');",
    )
    add_tf(
        l2,
        "UPDATE modifie des lignes existantes qui correspondent à une condition.",
        True,
        1,
        hint="UPDATE table SET col = val WHERE …",
        explanation="UPDATE users SET actif = true WHERE id = 5 — toujours un WHERE pour cibler !",
    )
    add_mc(
        l2,
        "DELETE FROM users SANS clause WHERE :",
        [
            ("Supprime une ligne aléatoire", False),
            ("Supprime TOUTES les lignes de la table", True),
            ("Ne fait rien", False),
            ("Supprime la table entière", False),
        ],
        2,
        hint="DANGER — comme vider le tableau Excel",
        explanation="DELETE sans WHERE = catastrophe en production. DROP TABLE supprime la structure.",
    )
    add_fill(
        l2,
        "Pour compter les lignes par catégorie : GROUP ???",
        "by",
        3,
        hint="GROUP BY — regrouper puis agréger",
        explanation="SELECT categorie, COUNT(*) FROM produits GROUP BY categorie;",
    )
    add_mc(
        l2,
        "COUNT(*) dans SELECT retourne :",
        [
            ("Le nombre de lignes du groupe ou de la table", True),
            ("La somme des valeurs", False),
            ("Le nom des colonnes", False),
            ("L'index primaire", False),
        ],
        4,
        hint="Fonction d'agrégation classique",
        explanation="COUNT(*) compte les lignes. SUM(), AVG(), MAX(), MIN() pour d'autres stats.",
    )

    l3 = create_lesson(
        u1,
        "Relations et JOIN — Lier plusieurs tables",
        "Clés primaires et étrangères : relier auteurs et livres",
        3,
        35,
    )
    add_mc(
        l3,
        "Quel JOIN retourne uniquement les lignes qui ont une correspondance dans BOTH tables ?",
        [
            ("LEFT JOIN", False),
            ("INNER JOIN", True),
            ("FULL JOIN", False),
            ("CROSS JOIN", False),
        ],
        0,
        hint="Intersection — seulement les matchs",
        explanation="INNER JOIN : lignes présentes dans A ET B selon la condition de jointure.",
    )
    add_tf(
        l3,
        "Une clé primaire (PRIMARY KEY) identifie chaque ligne de façon unique.",
        True,
        1,
        hint="Un id auto-incrémenté typiquement",
        explanation="PRIMARY KEY garantit unicité et non-null. Chaque table a idéalement une PK.",
    )
    add_mc(
        l3,
        "Une clé étrangère (FOREIGN KEY) :",
        [
            ("Chiffre les données", False),
            ("Référence une clé primaire d'une autre table", True),
            ("Indexe automatiquement toutes les colonnes", False),
            ("Supprime les doublons", False),
        ],
        2,
        hint="Lien entre deux tables",
        explanation="orders.user_id REFERENCES users(id) — intégrité référentielle.",
    )
    add_fill(
        l3,
        "Relation un auteur, plusieurs livres : one-to-???",
        "many",
        3,
        hint="Un à plusieurs",
        explanation="One-to-many : 1 auteur → N livres. Many-to-many nécessite une table de liaison.",
    )
    add_mc(
        l3,
        "LEFT JOIN retourne :",
        [
            ("Toutes les lignes de la table de gauche, même sans correspondance", True),
            ("Seulement les correspondances", False),
            ("Uniquement la table de droite", False),
            ("Aucune ligne", False),
        ],
        4,
        hint="Gauche = priorité — les NULL si pas de match à droite",
        explanation="LEFT JOIN garde tous les clients même sans commande — utile pour « clients sans achat ».",
    )


def load_git():
    track = create_track(
        "Git & Collaboration",
        "git-collaboration",
        "Git enregistre l'historique de votre code comme une machine à remonter le temps — "
        "branches, commits et travail en équipe.",
        "📦",
        "#F05032",
        7,
    )

    u1 = create_unit(
        track,
        "Étape 1 — Versionner son code",
        "init, add, commit : les trois commandes du début",
        1,
    )

    l1 = create_lesson(
        u1,
        "Les bases de Git",
        "Un dépôt Git = un journal de toutes les versions de votre projet",
        1,
        30,
    )
    add_mc(
        l1,
        "Quelle commande initialise un nouveau dépôt Git dans le dossier courant ?",
        [
            ("git start", False),
            ("git init", True),
            ("git new", False),
            ("git create", False),
        ],
        0,
        hint="Init = initialiser",
        explanation="git init crée le dossier caché .git qui stocke tout l'historique.",
    )
    add_mc(
        l1,
        "git add place les fichiers dans :",
        [
            ("Le commit final directement", False),
            ("La staging area (zone de préparation)", True),
            ("La branche main automatiquement", False),
            ("Le dépôt distant (remote)", False),
        ],
        1,
        hint="Index — comme une liste de courses avant le commit",
        explanation="Workflow : modifier → git add (staging) → git commit (snapshot permanent).",
    )
    add_fill(
        l1,
        "Pour enregistrer un snapshot : git ??? -m 'message'",
        "commit",
        2,
        hint="Commit = engagement, enregistrement",
        explanation="git commit -m 'Ajout login' crée un point dans l'historique avec un message clair.",
    )
    add_tf(
        l1,
        "Chaque commit Git a un identifiant unique (hash SHA).",
        True,
        3,
        hint="Ex: a1b2c3d4…",
        explanation="L'historique est une chaîne de commits identifiés par hash — traçabilité totale.",
    )
    add_mc(
        l1,
        "git status affiche :",
        [
            ("Les fichiers modifiés, stagés et non suivis", True),
            ("Uniquement les branches", False),
            ("La vitesse du réseau", False),
            ("Les erreurs de compilation", False),
        ],
        4,
        hint="Votre tableau de bord Git",
        explanation="status = où en est votre working directory par rapport au dernier commit.",
    )

    l2 = create_lesson(
        u1,
        "Branches et fusion",
        "Travailler en parallèle sans casser la version stable",
        2,
        35,
    )
    add_mc(
        l2,
        "Quelle commande crée ET bascule sur une nouvelle branche ?",
        [
            ("git branch new", False),
            ("git checkout -b feature", True),
            ("git switch create", False),
            ("git new branch", False),
        ],
        0,
        hint="checkout -b ou switch -c en Git moderne",
        explanation="git checkout -b feature ou git switch -c feature — branche isolée pour une fonctionnalité.",
    )
    add_tf(
        l2,
        "git merge intègre les commits d'une branche dans la branche courante.",
        True,
        1,
        hint="Fusionner feature dans main",
        explanation="Sur main : git merge feature — combine les historiques.",
    )
    add_mc(
        l2,
        "Un conflit de merge survient quand :",
        [
            ("Le réseau est lent", False),
            ("Deux branches modifient la même ligne incompatiblement", True),
            ("Un commit est vide", False),
            ("La branche est supprimée", False),
        ],
        2,
        hint="Git ne peut pas choisir automatiquement",
        explanation="Conflit = marqueurs <<<<<<< dans le fichier. Vous résolvez puis commit.",
    )
    add_fill(
        l2,
        "Plateforme populaire pour héberger des dépôts Git : Git???",
        "github",
        3,
        hint="GitHub, GitLab, Bitbucket…",
        explanation="GitHub héberge des millions de dépôts — pull requests, issues, CI/CD.",
    )
    add_mc(
        l2,
        "La branche main (ou master) représente typiquement :",
        [
            ("La version stable / production du projet", True),
            ("Uniquement les tests", False),
            ("Les fichiers temporaires", False),
            ("L'historique supprimé", False),
        ],
        4,
        hint="Ligne principale de développement",
        explanation="Convention : main = stable. feature/* = travail en cours fusionné après revue.",
    )

    u2 = create_unit(
        track,
        "Étape 2 — Travailler à distance",
        "push, pull et collaborer sur un dépôt partagé",
        2,
    )

    l3 = create_lesson(
        u2,
        "Remote, push et pull",
        "Synchroniser votre machine avec GitHub ou GitLab",
        1,
        30,
    )
    add_mc(
        l3,
        "git remote add origin URL lie votre dépôt local à :",
        [
            ("Un dépôt distant (serveur)", True),
            ("Une branche locale", False),
            ("Un commit spécifique", False),
            ("Un fichier .gitignore", False),
        ],
        0,
        hint="origin = nom par défaut du remote",
        explanation="origin pointe vers GitHub/GitLab. git push origin main envoie vos commits.",
    )
    add_tf(
        l3,
        "git pull récupère les commits distants ET fusionne dans votre branche courante.",
        True,
        1,
        hint="fetch + merge (ou rebase)",
        explanation="pull = fetch + merge. Toujours pull avant push pour éviter des conflits.",
    )
    add_mc(
        l3,
        "git clone URL :",
        [
            ("Copie un dépôt distant complet sur votre machine", True),
            ("Supprime le dépôt distant", False),
            ("Crée une branche vide", False),
            ("Compile le projet", False),
        ],
        2,
        hint="Premier pas pour contribuer à un projet existant",
        explanation="git clone https://github.com/…/repo.git — historique complet inclus.",
    )
    add_fill(
        l3,
        "Pour envoyer vos commits au serveur : git ??? origin main",
        "push",
        3,
        hint="Pousser vers le remote",
        explanation="git push origin main — origin = remote, main = branche.",
    )
    add_mc(
        l3,
        "Un fichier .gitignore liste :",
        [
            ("Les fichiers que Git ne doit pas suivre", True),
            ("Les commits obligatoires", False),
            ("Les branches protégées", False),
            ("Les mots de passe chiffrés", False),
        ],
        4,
        hint="node_modules/, .env, __pycache__/…",
        explanation=".gitignore évite de committer secrets, dépendances et fichiers générés.",
    )

    l4 = create_lesson(
        u2,
        "Pull requests et bonnes pratiques",
        "Revue de code et collaboration en équipe",
        2,
        30,
    )
    add_tf(
        l4,
        "Une Pull Request (PR) permet à l'équipe de revoir les changements avant fusion.",
        True,
        0,
        hint="Merge après approbation",
        explanation="PR = proposition de fusion. Discussion, tests CI, puis merge dans main.",
    )
    add_mc(
        l4,
        "git log affiche :",
        [
            ("L'historique des commits", True),
            ("Les fichiers ignorés", False),
            ("La configuration remote", False),
            ("Les permissions du dépôt", False),
        ],
        1,
        hint="Journal des snapshots",
        explanation="git log --oneline pour un résumé. git log -p pour voir les diffs.",
    )
    add_mc(
        l4,
        "git diff sans arguments montre :",
        [
            ("Les différences non stagées (working dir vs staging)", True),
            ("Uniquement les branches", False),
            ("Les remotes", False),
            ("Les tags", False),
        ],
        2,
        hint="Ce qui a changé depuis le dernier add",
        explanation="git diff — modifications pas encore dans staging. git diff --staged après add.",
    )
    add_tf(
        l4,
        "Écrire des messages de commit clairs aide toute l'équipe à comprendre l'historique.",
        True,
        3,
        hint="« Fix login timeout » plutôt que « fix »",
        explanation="Bon commit = une intention claire. Facilite debug et revue de code.",
    )
    add_mc(
        l4,
        "git stash permet de :",
        [
            ("Mettre de côté temporairement des modifications non commitées", True),
            ("Supprimer toutes les branches", False),
            ("Chiffrer le dépôt", False),
            ("Publier sur npm", False),
        ],
        4,
        hint="Rangez vos changements dans une « réserve »",
        explanation="stash = sauvegarde temporaire. git stash pop pour les réappliquer.",
    )
