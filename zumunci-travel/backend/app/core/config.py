from functools import lru_cache
from itertools import permutations

from pydantic_settings import BaseSettings, SettingsConfigDict

# 8 régions administratives du Niger (+ villes secondaires fréquentes)
NIGER_REGIONS = [
    "Agadez",
    "Diffa",
    "Dosso",
    "Maradi",
    "Tahoua",
    "Tillabéri",
    "Zinder",
    "Niamey",
]

NIGER_SERVICE_CITIES = [
    "Niamey",
    "Maradi",
    "Zinder",
    "Tahoua",
    "Agadez",
    "Dosso",
    "Diffa",
    "Tillabéri",
    "Birni N'Konni",
    "Tessaoua",
    "Gaya",
    "Arlit",
    "Madaoua",
    "Magaria",
    "Filingué",
    "N'Guigmi",
    "Tchin-Tabaraden",
    "Ayorou",
]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "ZumunciTravel"
    app_env: str = "development"
    secret_key: str = "change-me-in-production-niger-zumunci-2026"
    access_token_expire_minutes: int = 60 * 24 * 7
    algorithm: str = "HS256"
    database_url: str = "sqlite:///./zumunci.db"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000"
    currency: str = "XOF"
    default_country: str = "NE"
    mobile_money_providers: str = "orange_money,airtel_money,moov_money,cash"

    # Couverture nationale : toutes les régions
    pilot_mode: bool = True
    pilot_hub: str = "Niamey"
    national_coverage: bool = True
    niger_regions: str = ",".join(NIGER_REGIONS)
    service_cities: str = ",".join(NIGER_SERVICE_CITIES)
    # Conservé pour compatibilité API ; généré dynamiquement si vide
    pilot_corridors: str = ""
    commission_rate: float = 0.10
    kyc_sla_hours: int = 24
    cash_allowed_modes: str = "bush_taxi,bus"
    night_start_hour: int = 20
    night_end_hour: int = 5
    default_locale: str = "fr-FR"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def payment_provider_list(self) -> list[str]:
        return [p.strip() for p in self.mobile_money_providers.split(",") if p.strip()]

    @property
    def cash_allowed_mode_list(self) -> list[str]:
        return [m.strip() for m in self.cash_allowed_modes.split(",") if m.strip()]

    @property
    def region_list(self) -> list[str]:
        return [r.strip() for r in self.niger_regions.split(",") if r.strip()]

    @property
    def service_city_list(self) -> list[str]:
        return [c.strip() for c in self.service_cities.split(",") if c.strip()]

    @property
    def pilot_corridor_pairs(self) -> list[tuple[str, str]]:
        """Tous les trajets entre chefs-lieux de région (couverture nationale)."""
        if self.pilot_corridors.strip():
            pairs: list[tuple[str, str]] = []
            for item in self.pilot_corridors.split(","):
                item = item.strip()
                if "-" not in item:
                    continue
                a, b = item.split("-", 1)
                pairs.append((a.strip(), b.strip()))
            return pairs
        # Toutes les paires entre les 8 régions
        return [(a, b) for a, b in permutations(self.region_list, 2)]


@lru_cache
def get_settings() -> Settings:
    return Settings()
