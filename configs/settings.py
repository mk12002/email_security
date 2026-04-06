"""
Centralized configuration management using Pydantic Settings.

Loads configuration from environment variables and .env file.
All settings are validated and typed at application startup.
"""

from pathlib import Path
from functools import lru_cache
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


# Project root directory
PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env file."""

    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Application ---
    app_env: str = Field(default="development", description="Application environment")
    app_debug: bool = Field(default=True, description="Debug mode flag")
    app_log_level: str = Field(default="INFO", description="Logging level")
    app_secret_key: str = Field(
        default="change-me-in-production", description="Application secret key"
    )

    # --- API Server ---
    api_host: str = Field(default="0.0.0.0", description="API server host")
    api_port: int = Field(default=8000, description="API server port")
    api_workers: int = Field(default=4, description="Number of API workers")

    # --- RabbitMQ ---
    rabbitmq_host: str = Field(default="rabbitmq", description="RabbitMQ host")
    rabbitmq_port: int = Field(default=5672, description="RabbitMQ AMQP port")
    rabbitmq_user: str = Field(default="guest", description="RabbitMQ username")
    rabbitmq_password: str = Field(default="guest", description="RabbitMQ password")
    new_email_exchange: str = Field(
        default="email.new.exchange", description="Exchange for new email events"
    )
    results_queue: str = Field(
        default="email.results.queue", description="Queue for agent results"
    )

    # --- Parser / Ingestion ---
    email_drop_dir: str = Field(
        default="/mnt/email_drop", description="Directory watched for raw email files"
    )
    attachment_volume_dir: str = Field(
        default="/mnt/attachments", description="Shared attachment volume path"
    )
    parser_poll_seconds: int = Field(
        default=2, description="Polling interval for parser worker"
    )

    # --- Azure OpenAI ---
    azure_openai_endpoint: Optional[str] = Field(
        default=None, description="Azure OpenAI endpoint"
    )
    azure_openai_api_key: Optional[str] = Field(
        default=None, description="Azure OpenAI API key"
    )
    azure_openai_deployment: Optional[str] = Field(
        default=None, description="Azure OpenAI model deployment name"
    )
    azure_openai_api_version: str = Field(
        default="2024-02-15-preview", description="Azure OpenAI API version"
    )

    # --- Threat Intelligence API Keys ---
    virustotal_api_key: Optional[str] = Field(
        default=None, description="VirusTotal API key"
    )
    google_safe_browsing_api_key: Optional[str] = Field(
        default=None, description="Google Safe Browsing API key"
    )
    otx_api_key: Optional[str] = Field(
        default=None, description="AlienVault OTX API key"
    )
    abuseipdb_api_key: Optional[str] = Field(
        default=None, description="AbuseIPDB API key"
    )
    enable_virustotal_url_lookup: bool = Field(
        default=False, description="Enable VirusTotal URL lookups in URL agent"
    )
    enable_google_safe_browsing_lookup: bool = Field(
        default=False, description="Enable Google Safe Browsing URL lookups"
    )
    enable_openphish_lookup: bool = Field(
        default=False, description="Enable OpenPhish feed URL lookups"
    )
    enable_urlhaus_lookup: bool = Field(
        default=False, description="Enable URLhaus URL lookups"
    )
    enable_otx_lookup: bool = Field(
        default=False, description="Enable AlienVault OTX IOC lookups"
    )
    enable_abuseipdb_lookup: bool = Field(
        default=False, description="Enable AbuseIPDB IP reputation lookups"
    )
    enable_malwarebazaar_lookup: bool = Field(
        default=False, description="Enable MalwareBazaar hash lookups"
    )
    enable_virustotal_hash_lookup: bool = Field(
        default=False, description="Enable VirusTotal hash lookups in threat intel"
    )
    external_lookup_timeout_seconds: float = Field(
        default=6.0, description="Timeout in seconds for external intel API calls"
    )
    external_lookup_max_indicators: int = Field(
        default=10, description="Max indicators per type for external intel lookups"
    )
    openphish_feed_url: str = Field(
        default="https://openphish.com/feed.txt", description="OpenPhish feed URL"
    )
    openphish_cache_ttl_seconds: int = Field(
        default=900, description="OpenPhish feed cache TTL in seconds"
    )
    urlhaus_api_url: str = Field(
        default="https://urlhaus-api.abuse.ch/v1/url/", description="URLhaus API endpoint"
    )
    otx_api_base_url: str = Field(
        default="https://otx.alienvault.com", description="AlienVault OTX API base URL"
    )
    abuseipdb_api_url: str = Field(
        default="https://api.abuseipdb.com/api/v2/check", description="AbuseIPDB check endpoint"
    )
    malwarebazaar_api_url: str = Field(
        default="https://mb-api.abuse.ch/api/v1/", description="MalwareBazaar API endpoint"
    )
    urlscan_api_key: Optional[str] = Field(
        default=None, description="URLScan.io API key"
    )
    shodan_api_key: Optional[str] = Field(
        default=None, description="Shodan API key"
    )

    # --- Model Paths ---
    header_model_path: str = Field(
        default="models/header_agent/", description="Header agent model path"
    )
    content_model_path: str = Field(
        default="models/content_agent/", description="Content agent model path"
    )
    url_model_path: str = Field(
        default="models/url_agent/", description="URL agent model path"
    )
    attachment_model_path: str = Field(
        default="models/attachment_agent/", description="Attachment agent model path"
    )
    sandbox_model_path: str = Field(
        default="models/sandbox_agent/", description="Sandbox agent model path"
    )
    threat_intel_model_path: str = Field(
        default="models/threat_intel_agent/", description="Threat intel model path"
    )
    user_behavior_model_path: str = Field(
        default="models/user_behavior_agent/", description="User behavior agent model path"
    )

    # --- Dataset Paths ---
    dataset_base_path: str = Field(
        default="datasets/", description="Base dataset directory"
    )
    processed_dataset_path: str = Field(
        default="datasets_processed/", description="Processed dataset directory"
    )

    # --- Database ---
    database_url: str = Field(
        default="postgresql://user:password@localhost:5432/email_security",
        description="Database connection URL",
    )

    # --- Redis ---
    redis_url: str = Field(
        default="redis://localhost:6379/0", description="Redis connection URL"
    )

    # --- Orchestrator Finalization Controls ---
    orchestrator_cache_ttl_seconds: int = Field(
        default=900,
        description="Redis TTL for per-analysis aggregated agent results",
    )
    orchestrator_partial_timeout_seconds: int = Field(
        default=90,
        description="Finalize with partial agent results after this many seconds",
    )
    orchestrator_min_agents_for_decision: int = Field(
        default=4,
        description="Minimum agent count required for timeout-based partial finalization",
    )

    # --- Logging ---
    log_dir: str = Field(default="logs/", description="Log output directory")
    log_format: str = Field(default="json", description="Log format (json or text)")
    log_rotation: str = Field(default="10 MB", description="Log rotation threshold")
    log_retention: str = Field(default="30 days", description="Log retention period")

    # --- Garuda Integration ---
    garuda_api_base_url: str = Field(
        default="http://garuda-agent:8088", description="Garuda API base URL"
    )
    garuda_timeout_seconds: int = Field(
        default=15, description="Garuda API request timeout"
    )
    garuda_retry_queue: str = Field(
        default="garuda.retry.queue", description="Queue for Garuda investigation retries"
    )
    garuda_dead_letter_queue: str = Field(
        default="garuda.dead.queue", description="Dead-letter queue for exhausted Garuda retries"
    )
    garuda_retry_max_attempts: int = Field(
        default=6, description="Maximum Garuda retry attempts before dead-lettering"
    )
    garuda_retry_base_seconds: int = Field(
        default=30, description="Base exponential-backoff delay in seconds for Garuda retries"
    )
    garuda_retry_max_seconds: int = Field(
        default=1800, description="Maximum backoff delay in seconds for Garuda retries"
    )

    # --- Action Layer Endpoints ---
    quarantine_api_url: Optional[str] = Field(
        default=None,
        description="Endpoint URL for quarantine action dispatch",
    )
    soc_alert_api_url: Optional[str] = Field(
        default=None,
        description="Endpoint URL for SOC alert dispatch",
    )

    # --- Threat Intel Local IOC DB ---
    ioc_db_path: str = Field(
        default="data/ioc_store.db",
        description="SQLite path for local IOC database",
    )
    ioc_refresh_seconds: int = Field(
        default=300,
        description="How often to refresh IOC DB from filesystem feeds",
    )
    ioc_stale_seconds: int = Field(
        default=1800,
        description="Alert threshold for stale IOC store freshness",
    )
    threat_intel_auto_refresh_enabled: bool = Field(
        default=True,
        description="Enable periodic IOC store refresh loop in API process",
    )

    # --- Sandbox Detonation ---
    sandbox_detonation_image: str = Field(
        default="python:3.11-slim", description="Container image used for sandbox detonation"
    )
    sandbox_timeout_seconds: int = Field(
        default=60, description="Max runtime for each sandbox detonation"
    )
    sandbox_allow_network: bool = Field(
        default=False, description="Allow outbound network from detonation containers"
    )
    sandbox_non_root_user: str = Field(
        default="65534:65534", description="UID:GID used inside detonation containers"
    )
    sandbox_memory_limit_mb: int = Field(
        default=256, description="Memory limit in MB for each detonation container"
    )
    sandbox_pids_limit: int = Field(
        default=128, description="PID limit for each detonation container"
    )
    sandbox_max_detonations: int = Field(
        default=5, description="Maximum attachments to detonate per email"
    )
    sandbox_cleanup_stale_seconds: int = Field(
        default=1800, description="Remove stale detonation containers older than this many seconds"
    )
    sandbox_enable_benign_bootstrap: bool = Field(
        default=True, description="Enable benign bootstrap rows during sandbox preprocessing"
    )
    sandbox_benign_bootstrap_max_rows: int = Field(
        default=5000, description="Maximum number of local benign bootstrap rows"
    )

    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.app_env.lower() == "production"

    @property
    def log_dir_path(self) -> Path:
        """Resolve absolute path for the log directory."""
        log_path = Path(self.log_dir)
        if not log_path.is_absolute():
            log_path = PROJECT_ROOT / log_path
        return log_path

    def validate_production_settings(self) -> list[str]:
        """Return list of warnings for unsafe production settings."""
        warnings = []
        if self.is_production and self.app_secret_key == "change-me-in-production":
            warnings.append(
                "CRITICAL: APP_SECRET_KEY is using the default value in production! "
                "Set a strong, unique secret key via the APP_SECRET_KEY environment variable."
            )
        if self.is_production and self.app_debug:
            warnings.append(
                "WARNING: APP_DEBUG is enabled in production. Set APP_DEBUG=false."
            )
        return warnings


@lru_cache()
def get_settings() -> Settings:
    """Return cached settings instance (singleton pattern)."""
    return Settings()


# Module-level singleton for convenience
settings = get_settings()
