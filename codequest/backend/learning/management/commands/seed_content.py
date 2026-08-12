"""Populate the database with CodeQuest IT learning content.

Run with::

    python manage.py seed_content

The command is idempotent: it wipes the existing curriculum (courses, units,
lessons and exercises) and recreates it from the definition below. User
accounts and their progress are left untouched.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand
from django.db import transaction

from learning.models import Course, Exercise, Lesson, Unit

MC = Exercise.Kind.MULTIPLE_CHOICE
TF = Exercise.Kind.TRUE_FALSE
FB = Exercise.Kind.FILL_BLANK


CURRICULUM = [
    {
        "title": "Les bases de la programmation (Python)",
        "slug": "python-bases",
        "icon": "🐍",
        "color": "#3776AB",
        "description": "Découvre les variables, les types, les boucles et les fonctions avec Python.",
        "units": [
            {
                "title": "Variables et types",
                "description": "Stocker et manipuler des données.",
                "lessons": [
                    {
                        "title": "Les variables",
                        "exercises": [
                            {
                                "kind": MC,
                                "prompt": "Quel symbole utilise-t-on pour affecter une valeur à une variable en Python ?",
                                "choices": ["==", "=", "=>", ":="],
                                "answer": "=",
                                "explanation": "En Python, `=` affecte une valeur ; `==` compare deux valeurs.",
                            },
                            {
                                "kind": MC,
                                "prompt": "Quel est le type de la valeur 42 en Python ?",
                                "choices": ["str", "float", "int", "bool"],
                                "answer": "int",
                                "explanation": "42 est un entier, donc de type `int`.",
                            },
                            {
                                "kind": FB,
                                "prompt": "Complète : pour afficher du texte à l'écran on utilise la fonction ____().",
                                "choices": [],
                                "answer": "print",
                                "explanation": "`print()` affiche une valeur sur la sortie standard.",
                            },
                        ],
                    },
                    {
                        "title": "Types de données",
                        "exercises": [
                            {
                                "kind": MC,
                                "prompt": "Quelle valeur est un booléen ?",
                                "choices": ["\"True\"", "1", "True", "0"],
                                "answer": "True",
                                "explanation": "`True` (sans guillemets) est un booléen ; \"True\" est une chaîne.",
                            },
                            {
                                "kind": TF,
                                "prompt": "La valeur 3.14 est de type float.",
                                "choices": ["Vrai", "Faux"],
                                "answer": "Vrai",
                                "explanation": "Les nombres à virgule sont de type `float`.",
                            },
                            {
                                "kind": FB,
                                "prompt": "La fonction ____() renvoie le type d'une variable.",
                                "choices": [],
                                "answer": "type",
                                "explanation": "`type(x)` renvoie la classe de l'objet x.",
                            },
                        ],
                    },
                ],
            },
            {
                "title": "Contrôle et boucles",
                "description": "Prendre des décisions et répéter des actions.",
                "lessons": [
                    {
                        "title": "Conditions",
                        "exercises": [
                            {
                                "kind": MC,
                                "prompt": "Quel mot-clé démarre une condition en Python ?",
                                "choices": ["when", "if", "switch", "cond"],
                                "answer": "if",
                                "explanation": "`if` introduit une condition, suivie éventuellement de `elif`/`else`.",
                            },
                            {
                                "kind": MC,
                                "prompt": "Que vaut l'expression `10 % 3` ?",
                                "choices": ["1", "3", "0", "3.33"],
                                "answer": "1",
                                "explanation": "`%` est le modulo : le reste de 10 / 3 est 1.",
                            },
                            {
                                "kind": TF,
                                "prompt": "L'indentation est significative en Python.",
                                "choices": ["Vrai", "Faux"],
                                "answer": "Vrai",
                                "explanation": "Python délimite les blocs par l'indentation et non par des accolades.",
                            },
                        ],
                    },
                    {
                        "title": "Boucles",
                        "exercises": [
                            {
                                "kind": MC,
                                "prompt": "Quelle boucle est idéale pour parcourir une liste ?",
                                "choices": ["for", "do", "repeat", "goto"],
                                "answer": "for",
                                "explanation": "`for element in liste:` parcourt chaque élément.",
                            },
                            {
                                "kind": FB,
                                "prompt": "Le mot-clé ____ interrompt immédiatement une boucle.",
                                "choices": [],
                                "answer": "break",
                                "explanation": "`break` sort de la boucle, `continue` passe à l'itération suivante.",
                            },
                        ],
                    },
                ],
            },
        ],
    },
    {
        "title": "Réseaux informatiques",
        "slug": "reseaux",
        "icon": "🌐",
        "color": "#0F9D58",
        "description": "Comprends TCP/IP, les adresses IP, le DNS et les protocoles du web.",
        "units": [
            {
                "title": "Fondamentaux TCP/IP",
                "description": "Le langage commun d'Internet.",
                "lessons": [
                    {
                        "title": "Adressage IP",
                        "exercises": [
                            {
                                "kind": MC,
                                "prompt": "Combien de bits contient une adresse IPv4 ?",
                                "choices": ["16", "32", "64", "128"],
                                "answer": "32",
                                "explanation": "IPv4 utilise 32 bits (4 octets), IPv6 utilise 128 bits.",
                            },
                            {
                                "kind": MC,
                                "prompt": "Quelle adresse est une adresse privée ?",
                                "choices": ["8.8.8.8", "192.168.1.10", "1.1.1.1", "142.250.74.238"],
                                "answer": "192.168.1.10",
                                "explanation": "192.168.0.0/16 fait partie des plages privées (RFC 1918).",
                            },
                            {
                                "kind": FB,
                                "prompt": "L'adresse de bouclage (localhost) est 127.0.0.____.",
                                "choices": [],
                                "answer": "1",
                                "explanation": "127.0.0.1 désigne la machine locale.",
                            },
                        ],
                    },
                    {
                        "title": "Protocoles de transport",
                        "exercises": [
                            {
                                "kind": MC,
                                "prompt": "Quel protocole garantit la livraison ordonnée des paquets ?",
                                "choices": ["UDP", "TCP", "ICMP", "ARP"],
                                "answer": "TCP",
                                "explanation": "TCP est fiable et orienté connexion ; UDP est rapide mais sans garantie.",
                            },
                            {
                                "kind": TF,
                                "prompt": "UDP établit une connexion avant d'envoyer des données.",
                                "choices": ["Vrai", "Faux"],
                                "answer": "Faux",
                                "explanation": "UDP est sans connexion : il envoie les datagrammes directement.",
                            },
                        ],
                    },
                ],
            },
            {
                "title": "Le Web et le DNS",
                "description": "Comment les noms de domaine et le HTTP fonctionnent.",
                "lessons": [
                    {
                        "title": "DNS et HTTP",
                        "exercises": [
                            {
                                "kind": MC,
                                "prompt": "À quoi sert le DNS ?",
                                "choices": [
                                    "Chiffrer le trafic",
                                    "Traduire un nom de domaine en adresse IP",
                                    "Router les paquets",
                                    "Compresser les pages",
                                ],
                                "answer": "Traduire un nom de domaine en adresse IP",
                                "explanation": "Le DNS résout par exemple example.com en 93.184.216.34.",
                            },
                            {
                                "kind": MC,
                                "prompt": "Quel port utilise HTTPS par défaut ?",
                                "choices": ["80", "21", "443", "22"],
                                "answer": "443",
                                "explanation": "HTTP utilise le port 80 et HTTPS le port 443.",
                            },
                            {
                                "kind": FB,
                                "prompt": "Le code HTTP ____ signifie « page non trouvée ».",
                                "choices": [],
                                "answer": "404",
                                "explanation": "404 Not Found indique que la ressource est introuvable.",
                            },
                        ],
                    },
                ],
            },
        ],
    },
    {
        "title": "Linux et ligne de commande",
        "slug": "linux",
        "icon": "🐧",
        "color": "#333333",
        "description": "Maîtrise le terminal, le système de fichiers et les permissions Linux.",
        "units": [
            {
                "title": "Le terminal",
                "description": "Se déplacer et manipuler des fichiers.",
                "lessons": [
                    {
                        "title": "Commandes de base",
                        "exercises": [
                            {
                                "kind": MC,
                                "prompt": "Quelle commande liste le contenu d'un répertoire ?",
                                "choices": ["cd", "ls", "pwd", "mv"],
                                "answer": "ls",
                                "explanation": "`ls` liste les fichiers ; `cd` change de dossier.",
                            },
                            {
                                "kind": FB,
                                "prompt": "La commande ____ affiche le répertoire courant.",
                                "choices": [],
                                "answer": "pwd",
                                "explanation": "`pwd` = print working directory.",
                            },
                            {
                                "kind": MC,
                                "prompt": "Quelle commande crée un nouveau répertoire ?",
                                "choices": ["touch", "mkdir", "rmdir", "cat"],
                                "answer": "mkdir",
                                "explanation": "`mkdir` crée un dossier ; `touch` crée un fichier vide.",
                            },
                        ],
                    },
                    {
                        "title": "Permissions",
                        "exercises": [
                            {
                                "kind": MC,
                                "prompt": "Quelle commande modifie les permissions d'un fichier ?",
                                "choices": ["chmod", "chown", "chgrp", "ls -l"],
                                "answer": "chmod",
                                "explanation": "`chmod` change les droits ; `chown` change le propriétaire.",
                            },
                            {
                                "kind": MC,
                                "prompt": "En notation octale, quel droit correspond à lecture+écriture+exécution ?",
                                "choices": ["5", "6", "7", "4"],
                                "answer": "7",
                                "explanation": "4 (r) + 2 (w) + 1 (x) = 7.",
                            },
                            {
                                "kind": TF,
                                "prompt": "La commande `sudo` exécute une commande avec les privilèges administrateur.",
                                "choices": ["Vrai", "Faux"],
                                "answer": "Vrai",
                                "explanation": "`sudo` = superuser do.",
                            },
                        ],
                    },
                ],
            },
        ],
    },
    {
        "title": "Cybersécurité",
        "slug": "cybersecurite",
        "icon": "🔒",
        "color": "#D93025",
        "description": "Apprends les bases de la sécurité : mots de passe, chiffrement et menaces.",
        "units": [
            {
                "title": "Principes de sécurité",
                "description": "Confidentialité, intégrité, disponibilité.",
                "lessons": [
                    {
                        "title": "Notions clés",
                        "exercises": [
                            {
                                "kind": MC,
                                "prompt": "Que signifie le « C » de la triade CIA en sécurité ?",
                                "choices": ["Contrôle", "Confidentialité", "Certificat", "Chiffrement"],
                                "answer": "Confidentialité",
                                "explanation": "CIA = Confidentiality, Integrity, Availability.",
                            },
                            {
                                "kind": MC,
                                "prompt": "Quelle attaque consiste à tromper un utilisateur par un faux email ?",
                                "choices": ["DDoS", "Phishing", "Brute force", "SQL injection"],
                                "answer": "Phishing",
                                "explanation": "Le phishing (hameçonnage) usurpe l'identité pour voler des informations.",
                            },
                            {
                                "kind": TF,
                                "prompt": "Réutiliser le même mot de passe partout est une bonne pratique.",
                                "choices": ["Vrai", "Faux"],
                                "answer": "Faux",
                                "explanation": "Un mot de passe unique par service limite l'impact d'une fuite.",
                            },
                        ],
                    },
                    {
                        "title": "Chiffrement",
                        "exercises": [
                            {
                                "kind": MC,
                                "prompt": "Le chiffrement symétrique utilise…",
                                "choices": [
                                    "Deux clés différentes",
                                    "Une seule clé partagée",
                                    "Aucune clé",
                                    "Un mot de passe public",
                                ],
                                "answer": "Une seule clé partagée",
                                "explanation": "En symétrique, la même clé chiffre et déchiffre (ex : AES).",
                            },
                            {
                                "kind": FB,
                                "prompt": "L'authentification à ____ facteurs renforce la sécurité des comptes.",
                                "choices": [],
                                "answer": "deux",
                                "explanation": "La 2FA ajoute un second facteur (code, application, clé physique).",
                            },
                        ],
                    },
                ],
            },
        ],
    },
]


class Command(BaseCommand):
    help = "Seed the database with CodeQuest IT learning content."

    @transaction.atomic
    def handle(self, *args, **options):
        # Reset the curriculum only (progress/users are preserved).
        Course.objects.all().delete()

        course_count = unit_count = lesson_count = exercise_count = 0
        for c_order, course_def in enumerate(CURRICULUM):
            course = Course.objects.create(
                title=course_def["title"],
                slug=course_def["slug"],
                description=course_def.get("description", ""),
                icon=course_def.get("icon", "💻"),
                color=course_def.get("color", "#58CC02"),
                order=c_order,
            )
            course_count += 1
            for u_order, unit_def in enumerate(course_def["units"]):
                unit = Unit.objects.create(
                    course=course,
                    title=unit_def["title"],
                    description=unit_def.get("description", ""),
                    order=u_order,
                )
                unit_count += 1
                for l_order, lesson_def in enumerate(unit_def["lessons"]):
                    lesson = Lesson.objects.create(
                        unit=unit,
                        title=lesson_def["title"],
                        order=l_order,
                        xp_reward=lesson_def.get("xp_reward", 10),
                    )
                    lesson_count += 1
                    for e_order, ex_def in enumerate(lesson_def["exercises"]):
                        Exercise.objects.create(
                            lesson=lesson,
                            kind=ex_def["kind"],
                            prompt=ex_def["prompt"],
                            choices=ex_def.get("choices", []),
                            answer=ex_def["answer"],
                            explanation=ex_def.get("explanation", ""),
                            order=e_order,
                        )
                        exercise_count += 1

        self.stdout.write(
            self.style.SUCCESS(
                f"Seed terminé : {course_count} cours, {unit_count} unités, "
                f"{lesson_count} leçons, {exercise_count} exercices."
            )
        )
