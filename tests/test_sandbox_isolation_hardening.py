"""Sandbox isolation hardening tests."""

from __future__ import annotations

from email_security.agents.sandbox_agent import agent as sandbox_agent
from email_security.configs.settings import Settings


def test_sandbox_falls_back_when_local_docker_disabled(monkeypatch) -> None:
    monkeypatch.setattr(sandbox_agent.settings, "sandbox_local_docker_enabled", False, raising=False)

    # Ensure this path never attempts local Docker.
    monkeypatch.setattr(
        sandbox_agent.docker,
        "from_env",
        lambda: (_ for _ in ()).throw(AssertionError("docker.from_env should not be called")),
    )

    result = sandbox_agent.analyze(
        {
            "attachments": [
                {
                    "filename": "urgent_invoice.pdf",
                    "path": "/nonexistent/urgent_invoice.pdf",
                }
            ]
        }
    )

    assert result["agent_name"] == "sandbox_agent"
    assert "sandbox_local_docker_disabled" in result["indicators"]
    assert result["confidence"] <= 0.45


def test_production_warns_when_local_docker_enabled() -> None:
    prod = Settings(
        app_env="production",
        sandbox_local_docker_enabled=True,
    )
    warnings = prod.validate_production_settings()
    assert any("SANDBOX_LOCAL_DOCKER_ENABLED" in item for item in warnings)
