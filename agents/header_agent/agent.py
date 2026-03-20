"""Header analysis agent with auth checks, look-alike domain detection, and ML anomaly scoring."""

from __future__ import annotations

from typing import Any

from Levenshtein import distance as levenshtein_distance

from agents.header_agent.feature_extractor import extract_features
from agents.header_agent.inference import predict
from agents.header_agent.model_loader import load_model
from services.logging_service import get_agent_logger

logger = get_agent_logger("header_agent")

TRUSTED_DOMAINS = {
    "microsoft.com",
    "google.com",
    "paypal.com",
    "amazon.com",
    "apple.com",
}

# Pre-load the ML model at module import time
try:
    _model = load_model()
except Exception:
    _model = None


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, round(value, 4)))


def _domain_from_sender(sender: str) -> str:
    if "@" not in sender:
        return ""
    return sender.split("@")[-1].strip().lower()


def analyze(data: dict[str, Any]) -> dict[str, Any]:
    logger.info("Starting analysis", agent="header_agent")
    headers = data.get("headers", {}) or {}
    auth = (headers.get("authentication_results") or "").lower()
    sender = headers.get("sender", "")
    sender_domain = _domain_from_sender(sender)
    received = headers.get("received", []) or []

    indicators: list[str] = []
    risk = 0.0

    # 1. Heuristic Setup
    if "spf=fail" in auth or "spf=softfail" in auth:
        risk += 0.25
        indicators.append("spf_failed")
    if "dkim=fail" in auth:
        risk += 0.2
        indicators.append("dkim_failed")
    if "dmarc=fail" in auth:
        risk += 0.25
        indicators.append("dmarc_failed")

    for trusted in TRUSTED_DOMAINS:
        if sender_domain and sender_domain != trusted and levenshtein_distance(sender_domain, trusted) <= 2:
            risk += 0.3
            indicators.append(f"lookalike_domain:{sender_domain}->{trusted}")
            break

    if len(received) <= 1:
        risk += 0.05
        indicators.append("short_smtp_trace")

    confidence = _clamp(0.65 + min(0.25, len(indicators) * 0.05))

    # 2. ML Prediction
    features = extract_features(data)
    ml_result = predict(features, _model)

    if ml_result["risk_score"] > 0:
        # Boost risk if ML model flags an anomaly
        if ml_result["risk_score"] > 0.5:
            risk = max(risk, ml_result["risk_score"])
            indicators.extend(ml_result["indicators"])
        
        # Adjust confidence based on ML confidence
        if ml_result["confidence"] > 0.5:
            confidence = max(confidence, ml_result["confidence"])

    result = {
        "agent_name": "header_agent",
        "risk_score": _clamp(risk),
        "confidence": _clamp(confidence),
        "indicators": indicators,
    }
    logger.info("Analysis complete", risk_score=result["risk_score"])
    return result
