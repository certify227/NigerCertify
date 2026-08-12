"""Charge l'intégralité du contenu pédagogique CodeQuest."""

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.db import transaction

from courses.content_data import CONTENT_LOADERS
from courses.models import Choice, Exercise, Lesson, Track, Unit

User = get_user_model()


class Command(BaseCommand):
    help = "Charge tout le contenu pédagogique (7 parcours, leçons et exercices)"

    def add_arguments(self, parser):
        parser.add_argument(
            "--force",
            action="store_true",
            help="Supprime tout le contenu existant et recharge",
        )

    @transaction.atomic
    def handle(self, *args, **options):
        if Track.objects.exists() and not options["force"]:
            self.stdout.write(
                self.style.WARNING(
                    "Contenu déjà présent. Utilisez --force pour tout recharger."
                )
            )
            return

        if options["force"]:
            self.stdout.write("Suppression du contenu existant...")
            Choice.objects.all().delete()
            Exercise.objects.all().delete()
            Lesson.objects.all().delete()
            Unit.objects.all().delete()
            Track.objects.all().delete()

        total_tracks = 0
        total_lessons = 0
        total_exercises = 0

        for loader in CONTENT_LOADERS:
            loader()
            total_tracks += 1

        total_lessons = Lesson.objects.count()
        total_exercises = Exercise.objects.count()

        if not User.objects.filter(username="demo").exists():
            User.objects.create_user(
                username="demo",
                email="demo@codequest.app",
                password="demo1234",
                first_name="Apprenant",
            )
            self.stdout.write(self.style.SUCCESS("Utilisateur démo : demo / demo1234"))

        self.stdout.write(self.style.SUCCESS(
            f"Contenu chargé : {total_tracks} parcours, "
            f"{total_lessons} leçons, {total_exercises} exercices"
        ))
