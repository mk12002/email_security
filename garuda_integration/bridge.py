"""
Bridge module for Garuda Threat Hunting framework integration.
"""

from __future__ import annotations

from typing import Any

import httpx

from configs.settings import settings
from services.logging_service import get_service_logger

logger = get_service_logger("garuda_bridge")


def trigger_garuda_investigation(decision: dict[str, Any]) -> dict[str, Any]:
    """Trigger endpoint hunting workflow when risk threshold is exceeded."""
    payload = {
        "analysis_id": decision.get("analysis_id"),
        "verdict": decision.get("verdict"),
        "overall_risk_score": decision.get("overall_risk_score"),
        "iocs": {
            "indicators": [
                item
                for result in decision.get("agent_results", [])
                for item in result.get("indicators", [])
            ][:50]
        },
    }

    try:
        with httpx.Client(timeout=settings.garuda_timeout_seconds) as client:
            response = client.post(f"{settings.garuda_api_base_url}/investigate", json=payload)
            response.raise_for_status()
            body = response.json()
            logger.info("Garuda investigation triggered", analysis_id=payload["analysis_id"])
            return {
                "status": "triggered",
                "response": body,
            }
    except Exception as exc:
        logger.warning("Garuda integration unavailable", error=str(exc))
        return {
            "status": "degraded",
            "response": {
                "message": "Garuda API unavailable; investigation should be queued for retry.",
                "error": str(exc),
            },
        }
