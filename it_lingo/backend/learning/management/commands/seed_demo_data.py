from django.core.management.base import BaseCommand

from learning.demo_seed import seed_demo_data


class Command(BaseCommand):
    help = "Populate the database with demo content for the ItLingo MVP."

    def handle(self, *args, **options):
        stats = seed_demo_data()
        self.stdout.write(
            self.style.SUCCESS(
                "Demo data created: "
                f"{stats['tracks']} tracks, "
                f"{stats['modules']} modules, "
                f"{stats['lessons']} lessons, "
                f"{stats['challenges']} challenges."
            )
        )
