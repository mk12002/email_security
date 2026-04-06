"""User interaction prediction agent for click-risk estimation."""

from __future__ import annotations

from typing import Any

from email_security.agents.user_behavior_agent.feature_extractor import extract_features
from email_security.agents.user_behavior_agent.inference import predict
from email_security.agents.user_behavior_agent.model_loader import load_model
from email_security.services.logging_service import get_agent_logger

logger = get_agent_logger("user_behavior_agent")

FAMILIAR_DOMAINS = {"company.com", "microsoft.com", "google.com", "github.com"}
URGENCY_TERMS = {"urgent", "immediately", "verify", "final notice", "action required"}

def _clamp(value: float) -> float:
    return max(0.0, min(1.0, round(value, 4)))

def analyze(data: dict[str, Any]) -> dict[str, Any]:
    logger.info("Starting analysis", agent="user_behavior_agent")

    headers = data.get("headers", {}) or {}
    subject = (headers.get("subject") or "").lower()
    sender = (headers.get("sender") or "").lower()

    sender_domain = sender.split("@")[-1] if "@" in sender else sender
    sender_familiarity = 1.0 if sender_domain in FAMILIAR_DOMAINS else 0.0
    urgency_hits = sum(1 for term in URGENCY_TERMS if term in subject)

    click_probability = 0.2
    click_probability += 0.25 * min(2, urgency_hits)
    click_probability += 0.2 * (1.0 - sender_familiarity)

    indicators = []
    if urgency_hits:
        indicators.append(f"subject_urgency_hits:{urgency_hits}")
    if sender_familiarity < 1.0:
        indicators.append("unfamiliar_sender_domain")

    heuristic_result = {
        "agent_name": "user_behavior_agent",
        "risk_score": _clamp(click_probability),
        "confidence": 0.72,
        "indicators": indicators or ["low_click_likelihood"],
    }

    # Execute deterministic ML inference based on offline dataset Graph
    features = extract_features(data)
    model = load_model()
    ml_prediction = predict(features, model=model)

    if ml_prediction.get("confidence", 0.0) > 0.0:
        # Fuse outputs allowing XGBoost explicit dominance given exact deterministic mapping
        final_risk = _clamp((0.85 * ml_prediction.get("risk_score", 0.0)) + (0.15 * heuristic_result["risk_score"]))
        final_confidence = _clamp(max(heuristic_result["confidence"], ml_prediction.get("confidence", 0.0)))
        final_indicators = list(set(heuristic_result["indicators"] + ml_prediction.get("indicators", [])))[:20]
    else:
        final_risk = heuristic_result["risk_score"]
        final_confidence = heuristic_result["confidence"]
        final_indicators = heuristic_result["indicators"]

    result = {
        "agent_name": "user_behavior_agent",
        "risk_score": final_risk,
        "confidence": final_confidence,
        "indicators": final_indicators,
    }

    logger.info("Analysis complete", risk_score=result["risk_score"])
    return result
