"""Content phishing detection agent using semantic heuristics and ML-ready hooks."""

from __future__ import annotations

from typing import Any

from email_security.agents.content_agent.feature_extractor import extract_features
from email_security.agents.content_agent.inference import predict
from email_security.agents.content_agent.model_loader import load_model
from email_security.agents.ml_runtime import clamp as _clamp
from email_security.services.logging_service import get_agent_logger

logger = get_agent_logger("content_agent")

PHISHING_PATTERNS = {
    "urgency": ["urgent", "immediately", "action required", "asap", "suspended"],
    "credential": ["verify account", "password", "login", "confirm identity", "mfa"],
    "financial": ["invoice", "payment", "wire", "bank", "refund"],
}





def analyze(data: dict[str, Any]) -> dict[str, Any]:
    logger.info("Starting analysis", agent="content_agent")
    body = (data.get("body", {}) or {}).get("plain", "")
    body_html = (data.get("body", {}) or {}).get("html", "")
    subject = (data.get("headers", {}) or {}).get("subject", "")

    combined = f"{subject}\n{body}\n{body_html}".lower()
    indicators: list[str] = []
    risk = 0.0

    for pattern_type, keywords in PHISHING_PATTERNS.items():
        hits = [term for term in keywords if term in combined]
        if hits:
            indicators.append(f"{pattern_type}_signals:{','.join(hits[:3])}")
            risk += min(0.25, 0.08 * len(hits))

    if len(combined) > 2500:
        risk += 0.05
        indicators.append("long_email_body")

    if "http" in combined and "click" in combined:
        risk += 0.12
        indicators.append("click_through_language")

    heuristic_result = {
        "agent_name": "content_agent",
        "risk_score": _clamp(risk),
        "confidence": _clamp(0.55 + min(0.35, len(indicators) * 0.05)),
        "indicators": indicators,
    }

    features = extract_features(data)
    model = load_model()
    ml_prediction = predict(features, model=model)

    if ml_prediction.get("confidence", 0.0) > 0.0:
        final_risk = _clamp((0.6 * ml_prediction.get("risk_score", 0.0)) + (0.4 * heuristic_result["risk_score"]))
        final_confidence = _clamp(max(heuristic_result["confidence"], ml_prediction.get("confidence", 0.0)))
        final_indicators = (heuristic_result["indicators"] + ml_prediction.get("indicators", []))[:20]
    else:
        final_risk = heuristic_result["risk_score"]
        final_confidence = heuristic_result["confidence"]
        final_indicators = heuristic_result["indicators"]

    result = {
        "agent_name": "content_agent",
        "risk_score": final_risk,
        "confidence": final_confidence,
        "indicators": final_indicators,
    }
    logger.info("Analysis complete", risk_score=result["risk_score"], used_ml=ml_prediction.get("confidence", 0.0) > 0)
    return result
