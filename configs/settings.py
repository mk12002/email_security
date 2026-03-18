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

    # --- Azure Service Bus ---
    azure_servicebus_connection_string: Optional[str] = Field(
        default=None, description="Azure Service Bus connection string"
    )
    azure_servicebus_queue_name: str = Field(
        default="email-analysis-queue", description="Service Bus queue name"
    )

    # --- Azure Storage ---
    azure_storage_connection_string: Optional[str] = Field(
        default=None, description="Azure Storage connection string"
    )
    azure_storage_container_name: str = Field(
        default="email-attachments", description="Blob storage container name"
    )

    # --- Azure Identity ---
    azure_tenant_id: Optional[str] = Field(
        default=None, description="Azure AD tenant ID"
    )
    azure_client_id: Optional[str] = Field(
        default=None, description="Azure AD client ID"
    )
    azure_client_secret: Optional[str] = Field(
        default=None, description="Azure AD client secret"
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
    abuseipdb_api_key: Optional[str] = Field(
        default=None, description="AbuseIPDB API key"
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
        default="models/user_behavior_agent/", description="User behavior model path"
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


@lru_cache()
def get_settings() -> Settings:
    """Return cached settings instance (singleton pattern)."""
    return Settings()


# Module-level singleton for convenience
settings = get_settings()
