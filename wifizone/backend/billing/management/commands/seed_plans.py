from decimal import Decimal

from django.core.management.base import BaseCommand

from billing.models import Plan


class Command(BaseCommand):
    help = "Crée les forfaits d'abonnement par défaut"

    def handle(self, *args, **options):
        plans = [
            {
                "slug": "starter",
                "name": "Starter",
                "description": "Idéal pour débuter avec une petite zone WiFi.",
                "price_monthly": Decimal("15000"),
                "max_routers": 1,
                "max_vouchers_month": 200,
                "max_profiles": 5,
                "features": [
                    "1 routeur MikroTik",
                    "200 vouchers / mois",
                    "5 profils utilisateurs",
                    "Rapports de base",
                    "Support email",
                ],
                "sort_order": 1,
            },
            {
                "slug": "pro",
                "name": "Pro",
                "description": "Pour opérateurs avec plusieurs points d'accès.",
                "price_monthly": Decimal("45000"),
                "max_routers": 5,
                "max_vouchers_month": 2000,
                "max_profiles": 20,
                "features": [
                    "5 routeurs MikroTik",
                    "2 000 vouchers / mois",
                    "20 profils utilisateurs",
                    "Rapports avancés",
                    "Impression vouchers",
                    "Support prioritaire",
                ],
                "is_highlighted": True,
                "sort_order": 2,
            },
            {
                "slug": "enterprise",
                "name": "Enterprise",
                "description": "Solution complète pour grands opérateurs.",
                "price_monthly": Decimal("120000"),
                "max_routers": 50,
                "max_vouchers_month": 50000,
                "max_profiles": 100,
                "features": [
                    "50 routeurs MikroTik",
                    "50 000 vouchers / mois",
                    "100 profils utilisateurs",
                    "API & exports",
                    "Multi-utilisateurs",
                    "Support dédié",
                ],
                "sort_order": 3,
            },
        ]

        for data in plans:
            slug = data["slug"]
            defaults = {k: v for k, v in data.items() if k != "slug"}
            plan, created = Plan.objects.update_or_create(slug=slug, defaults=defaults)
            action = "Créé" if created else "Mis à jour"
            self.stdout.write(self.style.SUCCESS(f"{action}: {plan.name}"))
