"""Charge des parcours et exercices de démonstration (alias vers seed_full_content)."""

from django.core.management import call_command
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Charge les données de démonstration CodeQuest (délègue à seed_full_content)"

    def add_arguments(self, parser):
        parser.add_argument("--force", action="store_true", help="Recharge tout le contenu")

    def handle(self, *args, **options):
        call_command("seed_full_content", force=options["force"])
