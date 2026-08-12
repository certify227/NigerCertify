"""Seed CodeLingo with real computer-science learning content (in French)."""

from django.core.management.base import BaseCommand
from django.db import transaction

from learning.models import Course, Exercise, Lesson, Unit

# ---------------------------------------------------------------------------
# Content definition
# Structure:
# course -> units -> lessons -> exercises
# Each exercise: (type, question, choices, correct_answer, explanation)
# ---------------------------------------------------------------------------

MC = Exercise.Type.MULTIPLE_CHOICE
TF = Exercise.Type.TRUE_FALSE
FB = Exercise.Type.FILL_BLANK
TA = Exercise.Type.TYPE_ANSWER


COURSES = [
    {
        "title": "Python",
        "subtitle": "Les bases de la programmation",
        "description": "Apprends à programmer avec Python, du premier print aux fonctions.",
        "icon": "🐍",
        "color": "#3776AB",
        "units": [
            {
                "title": "Premiers pas",
                "description": "Variables, types et affichage",
                "lessons": [
                    {
                        "title": "Afficher du texte",
                        "exercises": [
                            (MC, "Quelle fonction affiche du texte à l'écran en Python ?",
                             ["echo()", "print()", "console.log()", "printf()"],
                             "print()",
                             "En Python, print() écrit sur la sortie standard."),
                            (FB, "Complète : ____(\"Bonjour\") affiche Bonjour.",
                             [], "print",
                             "print(\"Bonjour\") affiche Bonjour."),
                            (TF, "En Python, les instructions se terminent obligatoirement par un point-virgule.",
                             ["Vrai", "Faux"], "Faux",
                             "Python utilise les sauts de ligne, pas les points-virgules obligatoires."),
                        ],
                    },
                    {
                        "title": "Les variables",
                        "exercises": [
                            (MC, "Quel symbole assigne une valeur à une variable ?",
                             ["==", "=>", "=", ":="], "=",
                             "= est l'opérateur d'affectation."),
                            (MC, "Quel est le type de la valeur 42 ?",
                             ["str", "int", "float", "bool"], "int",
                             "42 est un entier (int)."),
                            (FB, "Complète : nom = ____ crée une chaîne vide.",
                             [], '""',
                             'Une chaîne vide s\'écrit "" ou \'\'.'),
                        ],
                    },
                ],
            },
            {
                "title": "Contrôle du flux",
                "description": "Conditions et boucles",
                "lessons": [
                    {
                        "title": "Les conditions",
                        "exercises": [
                            (MC, "Quel mot-clé introduit une condition en Python ?",
                             ["when", "if", "case", "switch"], "if",
                             "if teste une condition."),
                            (MC, "Que vaut le résultat de 10 > 3 ?",
                             ["True", "False", "10", "3"], "True",
                             "10 est bien supérieur à 3, donc True."),
                            (TF, "elif permet de tester une condition supplémentaire.",
                             ["Vrai", "Faux"], "Vrai",
                             "elif = else if, une condition alternative."),
                        ],
                    },
                    {
                        "title": "Les boucles",
                        "exercises": [
                            (MC, "Quelle boucle répète tant qu'une condition est vraie ?",
                             ["for", "while", "loop", "repeat"], "while",
                             "while boucle tant que la condition reste vraie."),
                            (FB, "Complète : for i in ____(5): parcourt 0 à 4.",
                             [], "range",
                             "range(5) génère 0,1,2,3,4."),
                            (TF, "break arrête complètement une boucle.",
                             ["Vrai", "Faux"], "Vrai",
                             "break sort immédiatement de la boucle."),
                        ],
                    },
                ],
            },
        ],
    },
    {
        "title": "Développement Web",
        "subtitle": "HTML, CSS et JavaScript",
        "description": "Construis des pages web modernes avec les technologies du front-end.",
        "icon": "🌐",
        "color": "#E44D26",
        "units": [
            {
                "title": "HTML",
                "description": "La structure des pages",
                "lessons": [
                    {
                        "title": "Les balises",
                        "exercises": [
                            (MC, "Que signifie HTML ?",
                             ["HyperText Markup Language", "High Tech Modern Language",
                              "Home Tool Markup Language", "Hyperlink Text Mode Language"],
                             "HyperText Markup Language",
                             "HTML = HyperText Markup Language."),
                            (MC, "Quelle balise crée un lien hypertexte ?",
                             ["<link>", "<a>", "<href>", "<url>"], "<a>",
                             "La balise <a href=...> crée un lien."),
                            (FB, "Complète : <____>Titre principal</h1> pour un grand titre.",
                             [], "h1",
                             "<h1> est le titre de niveau 1."),
                        ],
                    },
                ],
            },
            {
                "title": "CSS",
                "description": "Le style et la mise en forme",
                "lessons": [
                    {
                        "title": "Sélecteurs et propriétés",
                        "exercises": [
                            (MC, "Quelle propriété CSS change la couleur du texte ?",
                             ["background", "color", "font", "text-style"], "color",
                             "color définit la couleur du texte."),
                            (MC, "Quel sélecteur cible un élément par son id ?",
                             [".", "#", "*", "@"], "#",
                             "# cible un id, . cible une classe."),
                            (TF, "Flexbox aide à disposer des éléments en ligne ou colonne.",
                             ["Vrai", "Faux"], "Vrai",
                             "display:flex facilite l'agencement."),
                        ],
                    },
                ],
            },
            {
                "title": "JavaScript",
                "description": "L'interactivité",
                "lessons": [
                    {
                        "title": "Variables et fonctions",
                        "exercises": [
                            (MC, "Quel mot-clé déclare une variable modifiable en JS moderne ?",
                             ["var", "let", "const", "def"], "let",
                             "let déclare une variable de portée bloc modifiable."),
                            (MC, "Comment affiche-t-on un message dans la console ?",
                             ["print()", "echo()", "console.log()", "log.console()"],
                             "console.log()",
                             "console.log() écrit dans la console du navigateur."),
                            (TF, "=== compare la valeur ET le type en JavaScript.",
                             ["Vrai", "Faux"], "Vrai",
                             "=== est la comparaison stricte."),
                        ],
                    },
                ],
            },
        ],
    },
    {
        "title": "Réseaux",
        "subtitle": "TCP/IP, HTTP et DNS",
        "description": "Comprends comment les ordinateurs communiquent sur Internet.",
        "icon": "📡",
        "color": "#2980B9",
        "units": [
            {
                "title": "Fondamentaux",
                "description": "Adresses et protocoles",
                "lessons": [
                    {
                        "title": "Adresses IP",
                        "exercises": [
                            (MC, "Combien d'octets compose une adresse IPv4 ?",
                             ["2", "4", "6", "8"], "4",
                             "Une IPv4 fait 4 octets (32 bits), ex: 192.168.1.1."),
                            (MC, "Quel port utilise HTTPS par défaut ?",
                             ["21", "80", "443", "8080"], "443",
                             "HTTPS utilise le port 443."),
                            (TF, "Le protocole DNS traduit les noms de domaine en adresses IP.",
                             ["Vrai", "Faux"], "Vrai",
                             "Le DNS résout les noms en IP."),
                        ],
                    },
                    {
                        "title": "Le modèle OSI",
                        "exercises": [
                            (MC, "Combien de couches compte le modèle OSI ?",
                             ["4", "5", "7", "9"], "7",
                             "Le modèle OSI comporte 7 couches."),
                            (MC, "À quelle couche appartient le protocole IP ?",
                             ["Transport", "Réseau", "Liaison", "Application"], "Réseau",
                             "IP est un protocole de la couche réseau (3)."),
                            (FB, "Complète : ____ est le protocole de transport fiable et orienté connexion.",
                             [], "TCP",
                             "TCP est fiable et orienté connexion, contrairement à UDP."),
                        ],
                    },
                ],
            },
        ],
    },
    {
        "title": "Linux",
        "subtitle": "Ligne de commande et système",
        "description": "Maîtrise le terminal et les commandes essentielles de Linux.",
        "icon": "🐧",
        "color": "#333333",
        "units": [
            {
                "title": "Le terminal",
                "description": "Commandes de base",
                "lessons": [
                    {
                        "title": "Naviguer dans les fichiers",
                        "exercises": [
                            (MC, "Quelle commande liste le contenu d'un dossier ?",
                             ["ls", "cd", "pwd", "mkdir"], "ls",
                             "ls (list) affiche le contenu du répertoire."),
                            (MC, "Quelle commande change de répertoire ?",
                             ["mv", "cd", "cp", "rm"], "cd",
                             "cd (change directory) change de dossier."),
                            (FB, "Complète : ____ affiche le répertoire courant.",
                             [], "pwd",
                             "pwd = print working directory."),
                        ],
                    },
                    {
                        "title": "Gérer les fichiers",
                        "exercises": [
                            (MC, "Quelle commande supprime un fichier ?",
                             ["del", "rm", "erase", "unlink"], "rm",
                             "rm supprime des fichiers."),
                            (MC, "Quelle commande copie un fichier ?",
                             ["cp", "mv", "cat", "touch"], "cp",
                             "cp (copy) copie des fichiers."),
                            (TF, "chmod modifie les permissions d'un fichier.",
                             ["Vrai", "Faux"], "Vrai",
                             "chmod change les droits d'accès."),
                        ],
                    },
                ],
            },
        ],
    },
    {
        "title": "Bases de données",
        "subtitle": "SQL et modélisation",
        "description": "Interroge et structure des données avec le langage SQL.",
        "icon": "🗄️",
        "color": "#F29111",
        "units": [
            {
                "title": "SQL",
                "description": "Requêtes essentielles",
                "lessons": [
                    {
                        "title": "Lire des données",
                        "exercises": [
                            (MC, "Quelle instruction récupère des données ?",
                             ["GET", "SELECT", "FETCH", "READ"], "SELECT",
                             "SELECT lit des lignes d'une table."),
                            (FB, "Complète : SELECT * ____ utilisateurs; lit toute la table.",
                             [], "FROM",
                             "FROM indique la table source."),
                            (MC, "Quel mot-clé filtre les lignes ?",
                             ["FILTER", "WHERE", "HAVING", "IF"], "WHERE",
                             "WHERE filtre selon une condition."),
                        ],
                    },
                    {
                        "title": "Modifier des données",
                        "exercises": [
                            (MC, "Quelle instruction ajoute une nouvelle ligne ?",
                             ["ADD", "INSERT", "CREATE", "APPEND"], "INSERT",
                             "INSERT INTO ajoute des lignes."),
                            (MC, "Quelle instruction supprime des lignes ?",
                             ["DROP", "DELETE", "REMOVE", "CLEAR"], "DELETE",
                             "DELETE supprime des lignes; DROP supprime la table."),
                            (TF, "UPDATE modifie des lignes existantes.",
                             ["Vrai", "Faux"], "Vrai",
                             "UPDATE ... SET modifie des données."),
                        ],
                    },
                ],
            },
        ],
    },
    {
        "title": "Cybersécurité",
        "subtitle": "Bonnes pratiques et menaces",
        "description": "Découvre les concepts clés de la sécurité informatique.",
        "icon": "🔒",
        "color": "#C0392B",
        "units": [
            {
                "title": "Fondamentaux",
                "description": "Menaces et protection",
                "lessons": [
                    {
                        "title": "Les mots de passe",
                        "exercises": [
                            (MC, "Qu'est-ce qui rend un mot de passe plus robuste ?",
                             ["Sa longueur et sa complexité", "Utiliser son prénom",
                              "Le réutiliser partout", "Le noter sur un post-it"],
                             "Sa longueur et sa complexité",
                             "Longueur + variété de caractères = mot de passe fort."),
                            (TF, "L'authentification à deux facteurs (2FA) améliore la sécurité.",
                             ["Vrai", "Faux"], "Vrai",
                             "La 2FA ajoute une couche de vérification."),
                            (MC, "Qu'est-ce qu'une attaque par phishing ?",
                             ["Un virus réseau", "Une usurpation pour voler des infos",
                              "Un pare-feu", "Un antivirus"],
                             "Une usurpation pour voler des infos",
                             "Le phishing trompe l'utilisateur pour voler ses données."),
                        ],
                    },
                    {
                        "title": "Chiffrement",
                        "exercises": [
                            (MC, "À quoi sert le chiffrement ?",
                             ["Accélérer le réseau", "Rendre des données illisibles sans clé",
                              "Compresser des fichiers", "Sauvegarder des données"],
                             "Rendre des données illisibles sans clé",
                             "Le chiffrement protège la confidentialité."),
                            (FB, "Complète : le protocole ____ sécurise HTTP (le 'S' de HTTPS).",
                             [], "TLS",
                             "TLS (anciennement SSL) chiffre les échanges HTTPS."),
                            (TF, "Un hachage (hash) est réversible facilement.",
                             ["Vrai", "Faux"], "Faux",
                             "Un hachage est une fonction à sens unique."),
                        ],
                    },
                ],
            },
        ],
    },
]


class Command(BaseCommand):
    help = "Peuple la base avec les cours, unités, leçons et exercices de CodeLingo."

    def add_arguments(self, parser):
        parser.add_argument(
            "--flush",
            action="store_true",
            help="Supprime le contenu existant avant de recréer les cours.",
        )

    @transaction.atomic
    def handle(self, *args, **options):
        if options["flush"]:
            Course.objects.all().delete()
            self.stdout.write(self.style.WARNING("Contenu existant supprimé."))

        courses_created = lessons_created = exercises_created = 0

        for c_order, course_data in enumerate(COURSES):
            course, _ = Course.objects.update_or_create(
                title=course_data["title"],
                defaults={
                    "subtitle": course_data["subtitle"],
                    "description": course_data["description"],
                    "icon": course_data["icon"],
                    "color": course_data["color"],
                    "order": c_order,
                },
            )
            courses_created += 1

            for u_order, unit_data in enumerate(course_data["units"]):
                unit, _ = Unit.objects.update_or_create(
                    course=course,
                    title=unit_data["title"],
                    defaults={
                        "description": unit_data["description"],
                        "order": u_order,
                    },
                )

                for l_order, lesson_data in enumerate(unit_data["lessons"]):
                    lesson, _ = Lesson.objects.update_or_create(
                        unit=unit,
                        title=lesson_data["title"],
                        defaults={"order": l_order, "xp_reward": 10},
                    )
                    lessons_created += 1

                    lesson.exercises.all().delete()
                    for e_order, ex in enumerate(lesson_data["exercises"]):
                        ex_type, question, choices, answer, explanation = ex
                        Exercise.objects.create(
                            lesson=lesson,
                            exercise_type=ex_type,
                            question=question,
                            choices=choices,
                            correct_answer=answer,
                            explanation=explanation,
                            order=e_order,
                        )
                        exercises_created += 1

        self.stdout.write(
            self.style.SUCCESS(
                f"Seed terminé : {courses_created} cours, "
                f"{lessons_created} leçons, {exercises_created} exercices."
            )
        )
