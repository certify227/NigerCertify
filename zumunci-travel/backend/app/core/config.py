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

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def payment_provider_list(self) -> list[str]:
        return [p.strip() for p in self.mobile_money_providers.split(",") if p.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()