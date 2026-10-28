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
    google_client_id: str = ""

    # Gemini (Google AI Studio). An empty key disables AI analysis.
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.5-flash"
    gemini_timeout_seconds: float = 20.0
    ai_max_analyses_per_user_hour: int = 20

    # ── Wazuh integration ────────────────────────────────────────────────
    wazuh_opensearch_url: str = ""
    wazuh_api_user: str = ""
    wazuh_api_password: str = ""
    wazuh_index_pattern: str = "wazuh-alerts-*"
    wazuh_verify_ssl: bool = True
    wazuh_poll_interval_seconds: int = 300

    # ── Suricata integration ─────────────────────────────────────────────
    suricata_eve_url: str = ""
    suricata_poll_interval_seconds: int = 120

    # ── Notifications ────────────────────────────────────────────────────
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = "soc-dashboard@example.com"
    notify_on_severity: str = "critical,high"
    notify_rate_limit_per_minute: int = 10

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.cors_allowed_origins.split(",") if o.strip()]

    @property
    def notify_severities(self) -> set[str]:
        return {s.strip().lower() for s in self.notify_on_severity.split(",") if s.strip()}

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() in ("production", "prod")

    @property
    def wazuh_enabled(self) -> bool:
        return bool(self.wazuh_opensearch_url)

    @property
    def suricata_enabled(self) -> bool:
        return bool(self.suricata_eve_url)

    @property
    def telegram_enabled(self) -> bool:
        return bool(self.telegram_bot_token and self.telegram_chat_id)

    @property
    def smtp_enabled(self) -> bool:
        return bool(self.smtp_host)

    def jwt_secret(self) -> str:
        if len(self.jwt_secret_key) < 32:
            raise RuntimeError("JWT_SECRET_KEY must be set to at least 32 characters")
        return self.jwt_secret_key


@lru_cache
def get_settings() -> Settings:
    return Settings()
