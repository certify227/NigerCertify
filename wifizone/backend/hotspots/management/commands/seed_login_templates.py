from django.core.management.base import BaseCommand

from hotspots.models import HotspotLoginTemplate
from hotspots.services.login_template import DEFAULT_LOGIN_HTML


class Command(BaseCommand):
    help = "Crée les templates login hotspot système"

    def handle(self, *args, **options):
        templates = [
            {
                "slug": "modern-blue",
                "name": "Moderne Bleu",
                "description": "Design épuré avec fond sombre et accent bleu.",
                "primary_color": "#0d6efd",
                "background_color": "#1a1d23",
                "wifi_name": "WiFiZone",
            },
            {
                "slug": "warm-orange",
                "name": "Orange Chaleureux",
                "description": "Idéal pour cafés et restaurants.",
                "primary_color": "#fd7e14",
                "background_color": "#2d1f1a",
                "wifi_name": "WiFi Client",
            },
            {
                "slug": "minimal-white",
                "name": "Minimal Blanc",
                "description": "Simple et professionnel.",
                "primary_color": "#198754",
                "background_color": "#f4f6f9",
                "wifi_name": "WiFi Gratuit",
            },
        ]

        for data in templates:
            slug = data["slug"]
            defaults = {
                **data,
                "html_body": DEFAULT_LOGIN_HTML,
                "is_system": True,
                "owner": None,
                "is_active": True,
            }
            obj, created = HotspotLoginTemplate.objects.update_or_create(
                owner=None,
                slug=slug,
                defaults=defaults,
            )
            action = "Créé" if created else "Mis à jour"
            self.stdout.write(self.style.SUCCESS(f"{action}: {obj.name}"))
