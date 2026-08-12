"""Charge des parcours et exercices de démonstration."""

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand

from courses.models import Choice, Exercise, Lesson, Track, Unit

User = get_user_model()


class Command(BaseCommand):
    help = "Charge les données de démonstration CodeQuest"

    def handle(self, *args, **options):
        if Track.objects.exists():
            self.stdout.write(self.style.WARNING("Données déjà présentes, skip."))
            return

        # --- Parcours Python ---
        python_track = Track.objects.create(
            title="Python Fondamentaux",
            slug="python-fondamentaux",
            description="Apprenez les bases de Python : variables, types, conditions et boucles.",
            icon="🐍",
            color="#3776AB",
            order=1,
        )
        unit1 = Unit.objects.create(
            track=python_track,
            title="Variables & Types",
            description="Les briques de base du langage",
            order=1,
        )
        lesson1 = Lesson.objects.create(
            unit=unit1,
            title="Introduction aux variables",
            description="Déclarer et utiliser des variables en Python",
            order=1,
            xp_reward=25,
        )
        ex1 = Exercise.objects.create(
            lesson=lesson1,
            question="Quel mot-clé utilise-t-on pour déclarer une variable en Python ?",
            exercise_type="multiple_choice",
            hint="Pas besoin de mot-clé spécial en Python 3",
            explanation="En Python, on assigne directement : x = 10. Pas de var, let ou int.",
            order=0,
        )
        Choice.objects.bulk_create([
            Choice(exercise=ex1, text="var x = 10", is_correct=False, order=0),
            Choice(exercise=ex1, text="x = 10", is_correct=True, order=1),
            Choice(exercise=ex1, text="int x = 10", is_correct=False, order=2),
            Choice(exercise=ex1, text="declare x = 10", is_correct=False, order=3),
        ])
        ex2 = Exercise.objects.create(
            lesson=lesson1,
            question="Quel type Python représente un nombre entier ?",
            exercise_type="multiple_choice",
            explanation="int est le type des entiers en Python.",
            order=1,
        )
        Choice.objects.bulk_create([
            Choice(exercise=ex2, text="float", is_correct=False, order=0),
            Choice(exercise=ex2, text="int", is_correct=True, order=1),
            Choice(exercise=ex2, text="number", is_correct=False, order=2),
            Choice(exercise=ex2, text="integer", is_correct=False, order=3),
        ])
        ex3 = Exercise.objects.create(
            lesson=lesson1,
            question="En Python, les noms de variables sont sensibles à la casse.",
            exercise_type="true_false",
            explanation="myVar et myvar sont deux variables différentes.",
            order=2,
        )
        Choice.objects.bulk_create([
            Choice(exercise=ex3, text="Vrai", is_correct=True, order=0),
            Choice(exercise=ex3, text="Faux", is_correct=False, order=1),
        ])

        lesson2 = Lesson.objects.create(
            unit=unit1,
            title="Chaînes de caractères",
            description="Manipuler du texte avec str",
            order=2,
            xp_reward=25,
        )
        ex4 = Exercise.objects.create(
            lesson=lesson2,
            question="Quelle fonction convertit un nombre en chaîne ?",
            exercise_type="multiple_choice",
            explanation="str() convertit tout objet en représentation textuelle.",
            order=0,
        )
        Choice.objects.bulk_create([
            Choice(exercise=ex4, text="string()", is_correct=False, order=0),
            Choice(exercise=ex4, text="str()", is_correct=True, order=1),
            Choice(exercise=ex4, text="toString()", is_correct=False, order=2),
            Choice(exercise=ex4, text="text()", is_correct=False, order=3),
        ])

        # --- Parcours Réseaux ---
        net_track = Track.objects.create(
            title="Réseaux & TCP/IP",
            slug="reseaux-tcpip",
            description="Comprendre les protocoles, adresses IP et le modèle OSI.",
            icon="🌐",
            color="#1CB0F6",
            order=2,
        )
        net_unit = Unit.objects.create(
            track=net_track,
            title="Adressage IP",
            description="IPv4, masques et sous-réseaux",
            order=1,
        )
        net_lesson = Lesson.objects.create(
            unit=net_unit,
            title="IPv4 — Les bases",
            description="Structure d'une adresse IPv4",
            order=1,
            xp_reward=30,
        )
        ex5 = Exercise.objects.create(
            lesson=net_lesson,
            question="Combien d'octets comporte une adresse IPv4 ?",
            exercise_type="multiple_choice",
            explanation="IPv4 = 4 octets = 32 bits (ex: 192.168.1.1).",
            order=0,
        )
        Choice.objects.bulk_create([
            Choice(exercise=ex5, text="2", is_correct=False, order=0),
            Choice(exercise=ex5, text="4", is_correct=True, order=1),
            Choice(exercise=ex5, text="6", is_correct=False, order=2),
            Choice(exercise=ex5, text="8", is_correct=False, order=3),
        ])
        ex6 = Exercise.objects.create(
            lesson=net_lesson,
            question="Quel protocole associe un nom de domaine à une adresse IP ?",
            exercise_type="fill_blank",
            correct_answer="dns",
            explanation="DNS (Domain Name System) résout les noms en adresses IP.",
            order=1,
        )

        # --- Parcours Cybersécurité ---
        sec_track = Track.objects.create(
            title="Cybersécurité",
            slug="cybersecurite",
            description="OWASP, authentification, chiffrement et bonnes pratiques.",
            icon="🔒",
            color="#FF4B4B",
            order=3,
        )
        sec_unit = Unit.objects.create(
            track=sec_track,
            title="OWASP Top 10",
            description="Les vulnérabilités web les plus courantes",
            order=1,
        )
        sec_lesson = Lesson.objects.create(
            unit=sec_unit,
            title="Injection SQL",
            description="Comprendre et prévenir les injections",
            order=1,
            xp_reward=35,
        )
        ex7 = Exercise.objects.create(
            lesson=sec_lesson,
            question="L'injection SQL exploite des requêtes non paramétrées.",
            exercise_type="true_false",
            explanation="Les requêtes préparées (paramétrées) neutralisent ce risque.",
            order=0,
        )
        Choice.objects.bulk_create([
            Choice(exercise=ex7, text="Vrai", is_correct=True, order=0),
            Choice(exercise=ex7, text="Faux", is_correct=False, order=1),
        ])

        # Utilisateur démo
        if not User.objects.filter(username="demo").exists():
            user = User.objects.create_user(
                username="demo",
                email="demo@codequest.app",
                password="demo1234",
                first_name="Apprenant",
            )
            self.stdout.write(self.style.SUCCESS(f"Utilisateur démo créé : demo / demo1234"))

        self.stdout.write(self.style.SUCCESS("Données de démonstration chargées avec succès !"))
