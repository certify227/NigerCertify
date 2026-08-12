from django.core.management.base import BaseCommand

from learning.models import Challenge, Lesson, Track, Unit


class Command(BaseCommand):
    help = "Seed starter IT learning content."

    def handle(self, *args, **options):
        track, _ = Track.objects.update_or_create(
            slug="python-fundamentals",
            defaults={
                "title": "Fondamentaux Python",
                "description": "Apprends les bases de Python avec des mini-exercices courts et progressifs.",
                "icon": "code",
                "color": "#1cb0f6",
                "order": 1,
            },
        )
        unit, _ = Unit.objects.update_or_create(
            track=track,
            order=1,
            defaults={
                "title": "Premiers pas",
                "description": "Variables, types et logique de base.",
            },
        )
        lesson, _ = Lesson.objects.update_or_create(
            unit=unit,
            order=1,
            defaults={
                "title": "Variables et types",
                "summary": "Identifie les valeurs, les variables et les types Python.",
                "xp_reward": 15,
            },
        )

        challenges = [
            {
                "order": 1,
                "type": Challenge.ChallengeType.MULTIPLE_CHOICE,
                "prompt": "Quel type Python représente la valeur True ?",
                "choices": ["str", "bool", "int", "list"],
                "correct_answer": "bool",
                "explanation": "True et False sont des booléens, donc leur type est bool.",
            },
            {
                "order": 2,
                "type": Challenge.ChallengeType.FLASHCARD,
                "prompt": "Complète : une variable sert à ____ une valeur pour la réutiliser.",
                "choices": ["stocker", "compiler", "supprimer", "déployer"],
                "correct_answer": "stocker",
                "explanation": "Une variable donne un nom à une valeur stockée en mémoire.",
            },
            {
                "order": 3,
                "type": Challenge.ChallengeType.CODE_ORDER,
                "prompt": "Réordonne ces lignes pour afficher un message.",
                "choices": ["message = 'Bonjour ITLingo'", "print(message)"],
                "correct_answer": ["message = 'Bonjour ITLingo'", "print(message)"],
                "explanation": "On définit d’abord la variable, puis on l’utilise avec print().",
            },
        ]
        for challenge in challenges:
            Challenge.objects.update_or_create(
                lesson=lesson,
                order=challenge["order"],
                defaults=challenge,
            )

        self.stdout.write(self.style.SUCCESS("Starter learning content seeded."))
