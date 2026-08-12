"""Peuple la base avec un contenu pédagogique de démarrage (français, informatique)."""
from django.core.management.base import BaseCommand
from django.db import transaction

from courses.models import Choice, Course, Exercise, Lesson, Module


COURSES_DATA = [
    {
        "title": "Python : les bases",
        "slug": "python-bases",
        "language": "python",
        "icon": "🐍",
        "color": "#3776AB",
        "description": "Découvre les fondamentaux du langage Python.",
        "modules": [
            {
                "title": "Variables & types",
                "description": "Manipuler des variables, nombres et chaînes.",
                "lessons": [
                    {
                        "title": "Première variable",
                        "xp_reward": 10,
                        "exercises": [
                            {
                                "kind": "mcq",
                                "prompt": "Quelle instruction affiche 'Bonjour' à l'écran en Python 3 ?",
                                "explanation": "En Python 3, print est une fonction.",
                                "choices": [
                                    ("print('Bonjour')", True),
                                    ("echo 'Bonjour'", False),
                                    ("console.log('Bonjour')", False),
                                    ("printf('Bonjour')", False),
                                ],
                            },
                            {
                                "kind": "true_false",
                                "prompt": "En Python, `x = 10` crée une variable entière.",
                                "correct_answer": "true",
                                "explanation": "Le type est inféré automatiquement à partir de la valeur.",
                            },
                            {
                                "kind": "fill_blank",
                                "prompt": "Complète : pour obtenir la longueur d'une chaîne s, on écrit ____(s).",
                                "correct_answer": "len",
                                "explanation": "La fonction intégrée len renvoie la taille d'une séquence.",
                            },
                        ],
                    },
                    {
                        "title": "Opérations arithmétiques",
                        "xp_reward": 15,
                        "exercises": [
                            {
                                "kind": "code_output",
                                "prompt": "Que vaut le résultat de l'expression ci-dessous ?",
                                "code_snippet": "print(7 // 2)",
                                "correct_answer": "3",
                                "explanation": "// est la division entière, 7//2 = 3.",
                            },
                            {
                                "kind": "mcq",
                                "prompt": "Quel opérateur donne le reste d'une division ?",
                                "choices": [
                                    ("%", True),
                                    ("//", False),
                                    ("**", False),
                                    ("/", False),
                                ],
                                "explanation": "% est l'opérateur modulo.",
                            },
                        ],
                    },
                ],
            },
            {
                "title": "Contrôle de flux",
                "description": "Conditions et boucles.",
                "lessons": [
                    {
                        "title": "Les conditions",
                        "xp_reward": 15,
                        "exercises": [
                            {
                                "kind": "mcq",
                                "prompt": "Quelle est la syntaxe correcte d'une condition en Python ?",
                                "choices": [
                                    ("if x == 3:", True),
                                    ("if (x == 3)", False),
                                    ("if x = 3:", False),
                                    ("if x == 3 then", False),
                                ],
                                "explanation": "Python utilise ':' à la fin de la ligne et l'indentation.",
                            },
                            {
                                "kind": "code_output",
                                "prompt": "Que renvoie ce code ?",
                                "code_snippet": "x = 5\nif x > 3:\n    print('grand')\nelse:\n    print('petit')",
                                "correct_answer": "grand",
                                "explanation": "5 > 3 est vrai, la branche if est exécutée.",
                            },
                        ],
                    },
                    {
                        "title": "Les boucles for",
                        "xp_reward": 15,
                        "exercises": [
                            {
                                "kind": "code_output",
                                "prompt": "Combien de nombres seront affichés ?",
                                "code_snippet": "for i in range(5):\n    print(i)",
                                "correct_answer": "5",
                                "explanation": "range(5) génère 0,1,2,3,4 (5 valeurs).",
                            },
                            {
                                "kind": "true_false",
                                "prompt": "range(1, 10) inclut le nombre 10.",
                                "correct_answer": "false",
                                "explanation": "range(a, b) s'arrête à b-1.",
                            },
                        ],
                    },
                ],
            },
        ],
    },
    {
        "title": "Linux & terminal",
        "slug": "linux-terminal",
        "language": "linux",
        "icon": "🐧",
        "color": "#000000",
        "description": "Apprends les commandes essentielles du terminal Linux.",
        "modules": [
            {
                "title": "Commandes de base",
                "description": "Se déplacer et lister des fichiers.",
                "lessons": [
                    {
                        "title": "Naviguer",
                        "xp_reward": 10,
                        "exercises": [
                            {
                                "kind": "mcq",
                                "prompt": "Quelle commande affiche le répertoire courant ?",
                                "choices": [
                                    ("pwd", True),
                                    ("ls", False),
                                    ("cd", False),
                                    ("dir", False),
                                ],
                            },
                            {
                                "kind": "fill_blank",
                                "prompt": "Pour lister les fichiers cachés on utilise ls ____",
                                "correct_answer": "-a",
                                "explanation": "L'option -a affiche les fichiers commençant par '.'.",
                            },
                            {
                                "kind": "mcq",
                                "prompt": "Quelle commande crée un dossier ?",
                                "choices": [
                                    ("mkdir", True),
                                    ("touch", False),
                                    ("rmdir", False),
                                    ("mv", False),
                                ],
                            },
                        ],
                    },
                    {
                        "title": "Permissions",
                        "xp_reward": 15,
                        "exercises": [
                            {
                                "kind": "mcq",
                                "prompt": "Que fait `chmod +x script.sh` ?",
                                "choices": [
                                    ("Rend le fichier exécutable", True),
                                    ("Supprime le fichier", False),
                                    ("Chiffre le fichier", False),
                                    ("Change le propriétaire", False),
                                ],
                            },
                            {
                                "kind": "true_false",
                                "prompt": "La commande `sudo` permet d'exécuter une commande avec les privilèges root.",
                                "correct_answer": "true",
                            },
                        ],
                    },
                ],
            },
        ],
    },
    {
        "title": "Réseaux : bases TCP/IP",
        "slug": "reseaux-tcpip",
        "language": "network",
        "icon": "🌐",
        "color": "#1E90FF",
        "description": "Comprends comment fonctionnent les réseaux modernes.",
        "modules": [
            {
                "title": "Modèle OSI & TCP/IP",
                "description": "Couches et protocoles clés.",
                "lessons": [
                    {
                        "title": "Le modèle OSI",
                        "xp_reward": 15,
                        "exercises": [
                            {
                                "kind": "fill_blank",
                                "prompt": "Le modèle OSI comporte ____ couches.",
                                "correct_answer": "7",
                            },
                            {
                                "kind": "mcq",
                                "prompt": "À quelle couche appartient le protocole IP ?",
                                "choices": [
                                    ("Réseau (3)", True),
                                    ("Transport (4)", False),
                                    ("Liaison (2)", False),
                                    ("Application (7)", False),
                                ],
                            },
                            {
                                "kind": "mcq",
                                "prompt": "Quel protocole est orienté connexion et fiable ?",
                                "choices": [
                                    ("TCP", True),
                                    ("UDP", False),
                                    ("ICMP", False),
                                    ("ARP", False),
                                ],
                                "explanation": "TCP établit une connexion et garantit la livraison.",
                            },
                        ],
                    },
                    {
                        "title": "Adressage IP",
                        "xp_reward": 15,
                        "exercises": [
                            {
                                "kind": "true_false",
                                "prompt": "192.168.0.0/16 est un réseau privé.",
                                "correct_answer": "true",
                            },
                            {
                                "kind": "mcq",
                                "prompt": "Combien de bits contient une adresse IPv4 ?",
                                "choices": [
                                    ("32", True),
                                    ("64", False),
                                    ("128", False),
                                    ("16", False),
                                ],
                            },
                        ],
                    },
                ],
            },
        ],
    },
    {
        "title": "Git & GitHub",
        "slug": "git-github",
        "language": "git",
        "icon": "🔀",
        "color": "#F05032",
        "description": "Contrôle de version, branches et collaboration.",
        "modules": [
            {
                "title": "Premiers pas avec Git",
                "description": "Initialiser un dépôt et faire des commits.",
                "lessons": [
                    {
                        "title": "Commandes essentielles",
                        "xp_reward": 15,
                        "exercises": [
                            {
                                "kind": "mcq",
                                "prompt": "Quelle commande initialise un dépôt Git ?",
                                "choices": [
                                    ("git init", True),
                                    ("git start", False),
                                    ("git new", False),
                                    ("git create", False),
                                ],
                            },
                            {
                                "kind": "fill_blank",
                                "prompt": "Pour ajouter tous les fichiers à l'index : git ____ .",
                                "correct_answer": "add",
                            },
                            {
                                "kind": "true_false",
                                "prompt": "Un commit dans Git est identifié par un hash SHA.",
                                "correct_answer": "true",
                            },
                        ],
                    },
                ],
            },
        ],
    },
    {
        "title": "Cybersécurité : fondamentaux",
        "slug": "cybersecurite-fondamentaux",
        "language": "security",
        "icon": "🛡️",
        "color": "#8B0000",
        "description": "Concepts de base pour comprendre la sécurité informatique.",
        "modules": [
            {
                "title": "Concepts CIA",
                "description": "Confidentialité, intégrité, disponibilité.",
                "lessons": [
                    {
                        "title": "Le triangle CIA",
                        "xp_reward": 15,
                        "exercises": [
                            {
                                "kind": "mcq",
                                "prompt": "Que garantit l'intégrité ?",
                                "choices": [
                                    ("Que la donnée n'a pas été modifiée", True),
                                    ("Que la donnée reste secrète", False),
                                    ("Que la donnée est toujours accessible", False),
                                    ("Que la donnée est chiffrée", False),
                                ],
                            },
                            {
                                "kind": "mcq",
                                "prompt": "Quelle attaque vise la disponibilité ?",
                                "choices": [
                                    ("DDoS", True),
                                    ("Phishing", False),
                                    ("SQL Injection", False),
                                    ("XSS", False),
                                ],
                            },
                            {
                                "kind": "true_false",
                                "prompt": "Le hachage est un moyen de vérifier l'intégrité d'un fichier.",
                                "correct_answer": "true",
                            },
                        ],
                    },
                ],
            },
        ],
    },
]


class Command(BaseCommand):
    help = "Peuple la base avec des cours d'informatique de démonstration."

    def add_arguments(self, parser):
        parser.add_argument("--flush", action="store_true", help="Supprime le contenu existant.")

    @transaction.atomic
    def handle(self, *args, **options):
        if options["flush"]:
            self.stdout.write("Suppression du contenu existant…")
            Choice.objects.all().delete()
            Exercise.objects.all().delete()
            Lesson.objects.all().delete()
            Module.objects.all().delete()
            Course.objects.all().delete()

        created_courses = 0
        created_lessons = 0
        created_exercises = 0

        for c_order, course_data in enumerate(COURSES_DATA):
            course, _ = Course.objects.update_or_create(
                slug=course_data["slug"],
                defaults={
                    "title": course_data["title"],
                    "description": course_data["description"],
                    "language": course_data["language"],
                    "icon": course_data["icon"],
                    "color": course_data["color"],
                    "order": c_order,
                },
            )
            created_courses += 1

            for m_order, module_data in enumerate(course_data["modules"]):
                module, _ = Module.objects.update_or_create(
                    course=course,
                    order=m_order,
                    defaults={
                        "title": module_data["title"],
                        "description": module_data.get("description", ""),
                    },
                )

                for l_order, lesson_data in enumerate(module_data["lessons"]):
                    lesson, _ = Lesson.objects.update_or_create(
                        module=module,
                        order=l_order,
                        defaults={
                            "title": lesson_data["title"],
                            "description": lesson_data.get("description", ""),
                            "xp_reward": lesson_data.get("xp_reward", 10),
                        },
                    )
                    created_lessons += 1

                    lesson.exercises.all().delete()
                    for e_order, ex_data in enumerate(lesson_data["exercises"]):
                        exercise = Exercise.objects.create(
                            lesson=lesson,
                            kind=ex_data["kind"],
                            prompt=ex_data["prompt"],
                            code_snippet=ex_data.get("code_snippet", ""),
                            explanation=ex_data.get("explanation", ""),
                            correct_answer=ex_data.get("correct_answer", ""),
                            order=e_order,
                        )
                        created_exercises += 1
                        for c_pos, (text, is_correct) in enumerate(ex_data.get("choices", [])):
                            Choice.objects.create(
                                exercise=exercise,
                                text=text,
                                is_correct=is_correct,
                                order=c_pos,
                            )

        self.stdout.write(self.style.SUCCESS(
            f"OK — {created_courses} cours, {created_lessons} leçons, {created_exercises} exercices."
        ))
