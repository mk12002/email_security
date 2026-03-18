"""Content phishing detection agent using semantic heuristics and ML-ready hooks."""

from typing import Any

from services.logging_service import get_agent_logger

logger = get_agent_logger("content_agent")

PHISHING_PATTERNS = {
    "urgency": ["urgent", "immediately", "action required", "asap", "suspended"],
    "credential": ["verify account", "password", "login", "confirm identity", "mfa"],
    "financial": ["invoice", "payment", "wire", "bank", "refund"],
}


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, round(value, 4)))


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

    result = {
        "agent_name": "content_agent",
        "risk_score": _clamp(risk),
        "confidence": _clamp(0.55 + min(0.35, len(indicators) * 0.05)),
        "indicators": indicators,
    }
    logger.info("Analysis complete", risk_score=result["risk_score"])
    return result
