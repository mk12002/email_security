"""Sandbox behavior agent with ephemeral Docker detonation containers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import docker

from services.logging_service import get_agent_logger

logger = get_agent_logger("sandbox_agent")


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, round(value, 4)))


def analyze(data: dict[str, Any]) -> dict[str, Any]:
    logger.info("Starting analysis", agent="sandbox_agent")
    attachments = data.get("attachments", []) or []
    if not attachments:
        return {
            "agent_name": "sandbox_agent",
            "risk_score": 0.0,
            "confidence": 0.75,
            "indicators": ["no_attachments_for_sandbox"],
        }

    indicators: list[str] = []
    risk = 0.0

    try:
        docker_client = docker.from_env()
        for attachment in attachments[:3]:
            target = Path(attachment.get("path", ""))
            if not target.exists():
                continue

            container = docker_client.containers.run(
                image="alpine:3.19",
                command="sh -c 'ls -la /sample && sleep 2'",
                detach=True,
                remove=False,
                volumes={str(target.parent): {"bind": "/sample", "mode": "ro"}},
            )
            try:
                result = container.wait(timeout=60)
                logs = (container.logs(stdout=True, stderr=True) or b"").decode("utf-8", errors="replace")
                if result.get("StatusCode", 1) != 0:
                    risk += 0.2
                    indicators.append(f"detonation_nonzero_exit:{target.name}")
                if "No such file" in logs or "permission denied" in logs.lower():
                    risk += 0.1
                    indicators.append(f"sandbox_execution_anomaly:{target.name}")
            finally:
                container.stop(timeout=2)
                container.remove(force=True)

            if target.suffix.lower() in {".exe", ".dll", ".js", ".ps1"}:
                risk += 0.15
                indicators.append(f"risky_executable_attachment:{target.name}")

    except Exception as exc:
        indicators.append("docker_sandbox_unavailable")
        logger.warning("Sandbox unavailable, falling back to static behavior hints", error=str(exc))
        for attachment in attachments[:5]:
            filename = (attachment.get("filename") or "").lower()
            if any(token in filename for token in ["invoice", "payment", "urgent", "update"]):
                risk += 0.08
                indicators.append(f"suspicious_attachment_name:{filename}")

    result = {
        "agent_name": "sandbox_agent",
        "risk_score": _clamp(risk),
        "confidence": _clamp(0.45 if "docker_sandbox_unavailable" in indicators else 0.78),
        "indicators": indicators[:20],
    }
    logger.info("Analysis complete", risk_score=result["risk_score"])
    return result
