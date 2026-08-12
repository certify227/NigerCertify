"""Définition de tout le contenu pédagogique CodeQuest."""

from courses.content_foundation import load_python_fondamentaux, load_reseaux
from courses.content_foundation_part2 import (
    load_bases_de_donnees,
    load_cybersecurite,
    load_git,
    load_linux,
    load_web_dev,
)
from courses.content_helpers import (
    add_code,
    add_fill,
    add_mc,
    add_tf,
    create_lesson,
    create_track,
    create_unit,
)

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
