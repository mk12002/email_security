"""
Action layer for quarantine and alert responses.
"""

from __future__ import annotations

from typing import Any

import httpx

from services.logging_service import get_service_logger

logger = get_service_logger("response_engine")


def _safe_call(url: str, payload: dict[str, Any]) -> None:
    try:
        with httpx.Client(timeout=5) as client:
            client.post(url, json=payload)
    except Exception as exc:
        logger.warning("Action endpoint unavailable", url=url, error=str(exc))


def execute_actions(decision: dict[str, Any]) -> None:
    actions = decision.get("recommended_actions", [])
    analysis_id = decision.get("analysis_id")
    score = decision.get("overall_risk_score", 0.0)

    payload = {
        "analysis_id": analysis_id,
        "score": score,
        "verdict": decision.get("verdict"),
        "actions": actions,
    }

    if "quarantine" in actions:
        _safe_call("http://localhost:8091/quarantine", payload)
        logger.info("Quarantine action emitted", analysis_id=analysis_id)
    if "soc_alert" in actions or "trigger_garuda" in actions:
        _safe_call("http://localhost:8092/alerts", payload)
        logger.info("SOC alert action emitted", analysis_id=analysis_id)
