from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Environment-driven settings. Secrets have no defaults and must come from the environment."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "development"
    log_level: str = "INFO"
    database_url: str = ""
    cors_allowed_origins: str = "http://localhost:8080"
    monitoring_mode: str = "mock"

    # Authentication
    jwt_secret_key: str = ""
    jwt_algorithm: str = "HS256"
    jwt_access_token_minutes: int = 60

    # Gemini (Google AI Studio). An empty key disables AI analysis.
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.5-flash"
    gemini_timeout_seconds: float = 20.0
    ai_max_analyses_per_user_hour: int = 20

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.cors_allowed_origins.split(",") if o.strip()]

    def jwt_secret(self) -> str:
        if len(self.jwt_secret_key) < 32:
            raise RuntimeError("JWT_SECRET_KEY must be set to at least 32 characters")
        return self.jwt_secret_key


@lru_cache
def get_settings() -> Settings:
    return Settings()
