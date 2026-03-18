"""Bootstrap and configuration guard tests."""

from __future__ import annotations

from pathlib import Path


def test_env_template_exists() -> None:
    template = Path(__file__).resolve().parents[1] / ".env.template"
    assert template.exists(), ".env.template should exist for setup scripts"


def test_env_template_has_core_keys() -> None:
    template = Path(__file__).resolve().parents[1] / ".env.template"
    content = template.read_text(encoding="utf-8")

    required = [
        "RABBITMQ_HOST",
        "DATABASE_URL",
        "REDIS_URL",
        "AZURE_OPENAI_ENDPOINT",
        "AZURE_OPENAI_DEPLOYMENT",
        "QUARANTINE_API_URL",
        "SOC_ALERT_API_URL",
    ]
    for key in required:
        assert key in content, f"Missing required key in .env.template: {key}"
