"""Ajoute des exercices de code Python aux données existantes."""

from django.core.management.base import BaseCommand

from courses.models import Exercise, Lesson, Unit


class Command(BaseCommand):
    help = "Ajoute une leçon avec exercices code_challenge"

    def handle(self, *args, **options):
        unit = Unit.objects.filter(track__slug="python-fondamentaux").first()
        if not unit:
            self.stdout.write(self.style.ERROR("Parcours Python introuvable. Lancez seed_demo_data d'abord."))
            return

        lesson, created = Lesson.objects.get_or_create(
            unit=unit,
            title="Premier programme Python",
            defaults={
                "description": "Écrivez votre premier code Python",
                "order": 3,
                "xp_reward": 40,
            },
        )

        if Exercise.objects.filter(lesson=lesson, exercise_type="code_challenge").exists():
            self.stdout.write(self.style.WARNING("Exercices code déjà présents."))
            return

        Exercise.objects.create(
            lesson=lesson,
            question="Écrivez un programme qui affiche exactement : Bonjour CodeQuest",
            exercise_type="code_challenge",
            starter_code='print("Bonjour CodeQuest")',
            correct_answer="Bonjour CodeQuest",
            hint="Utilisez la fonction print()",
            explanation="print() affiche du texte dans la console.",
            order=0,
        )
        Exercise.objects.create(
            lesson=lesson,
            question="Calculez et affichez la somme de 7 et 5 (affichez uniquement le nombre)",
            exercise_type="code_challenge",
            starter_code="# Affichez le résultat de 7 + 5\n",
            correct_answer="12",
            hint="print(7 + 5)",
            explanation="En Python, + additionne deux nombres.",
            order=1,
        )
        Exercise.objects.create(
            lesson=lesson,
            question="Affichez les nombres de 1 à 3, un par ligne",
            exercise_type="code_challenge",
            starter_code="for i in range(1, 4):\n    print(i)\n",
            correct_answer="1\n2\n3",
            hint="Utilisez une boucle for avec range()",
            explanation="range(1, 4) génère 1, 2, 3. Chaque print() crée une nouvelle ligne.",
            order=2,
        )

        self.stdout.write(self.style.SUCCESS(f"Leçon « {lesson.title} » créée avec 3 exercices code !"))
