from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "MailRecon"
    database_url: str = "sqlite:///./data/mailrecon.db"
    hibp_api_key: str | None = None
    hibp_user_agent: str = "MailRecon/0.1 (local OSINT tool)"
    github_token: str | None = None
    gitlab_token: str | None = None
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.2:3b"
    enable_ollama: bool = False
    privacy_mode: bool = False
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    api_key: str | None = None
    max_concurrency: int = 8
    max_queue_depth: int = 100
    max_investigations_per_window: int = 10
    investigation_rate_window_seconds: float = 60.0
    request_timeout_seconds: float = 10.0
    execution_lease_seconds: int = 60
    worker_poll_interval_seconds: float = 0.5
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

@lru_cache
def get_settings() -> Settings:
    return Settings()
