from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


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

    # Décisions produit pilote
    pilot_mode: bool = True
    pilot_hub: str = "Niamey"
    pilot_corridors: str = (
        "Niamey-Maradi,Niamey-Dosso,Niamey-Tillabéri,Niamey-Tahoua,"
        "Maradi-Niamey,Dosso-Niamey,Tillabéri-Niamey,Tahoua-Niamey"
    )
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
    def pilot_corridor_pairs(self) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        for item in self.pilot_corridors.split(","):
            item = item.strip()
            if "-" not in item:
                continue
            a, b = item.split("-", 1)
            pairs.append((a.strip(), b.strip()))
        return pairs


@lru_cache
def get_settings() -> Settings:
    return Settings()
