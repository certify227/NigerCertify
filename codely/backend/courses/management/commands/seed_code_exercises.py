"""Ajoute des exercices de code Python (intégrés dans seed_full_content)."""

from django.core.management.base import BaseCommand

from courses.models import Exercise, Lesson


class Command(BaseCommand):
    help = "Obsolète — les exercices code sont dans seed_full_content. Commande conservée pour compatibilité."

    def handle(self, *args, **options):
        count = Exercise.objects.filter(exercise_type="code_challenge").count()
        if count > 0:
            self.stdout.write(self.style.SUCCESS(f"{count} exercices code déjà présents."))
        else:
            self.stdout.write(
                self.style.WARNING("Lancez : python manage.py seed_full_content --force")
            )
