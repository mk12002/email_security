"""User interaction prediction agent for click-risk estimation."""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

from email_security.src.agents.user_behavior_agent.feature_extractor import extract_features
from email_security.src.agents.user_behavior_agent.inference import predict
from email_security.src.agents.user_behavior_agent.model_loader import load_model
from email_security.src.agents.ml_runtime import clamp as _clamp
from email_security.src.agents.trust_signals import assess_transactional_legitimacy
from email_security.src.services.logging_service import get_agent_logger

logger = get_agent_logger("user_behavior_agent")

FAMILIAR_DOMAINS = {"company.com", "microsoft.com", "google.com", "github.com"}
URGENCY_TERMS = {"urgent", "immediately", "verify", "final notice", "action required"}

# High-risk TLDs commonly abused for phishing / malware staging
HIGH_RISK_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".ru", ".top", ".click", ".online", ".site",
    ".pw", ".cc", ".ws", ".info",
}



def analyze(data: dict[str, Any]) -> dict[str, Any]:
    logger.info("Starting analysis", agent="user_behavior_agent")

    headers = data.get("headers", {}) or {}
    subject = (headers.get("subject") or "").lower()
    sender = (headers.get("sender") or "").lower()

    sender_domain = sender.split("@")[-1] if "@" in sender else sender
    sender_familiarity = 1.0 if sender_domain in FAMILIAR_DOMAINS else 0.0
    urgency_hits = sum(1 for term in URGENCY_TERMS if term in subject)
    legitimacy = assess_transactional_legitimacy(data)

    click_probability = 0.2
    click_probability += 0.25 * min(2, urgency_hits)
    click_probability += 0.2 * (1.0 - sender_familiarity)
    indicators: list[str] = []

    # High-risk TLD check
    sender_tld = "." + sender_domain.rsplit(".", 1)[-1] if "." in sender_domain else ""
    if sender_tld and sender_tld in HIGH_RISK_TLDS:
        click_probability += 0.20
        indicators.append(f"high_risk_tld:{sender_tld}")

    # Domain-age check via WHOIS (optional — degrades gracefully if library unavailable)
    try:
        import whois  # type: ignore
        w = whois.whois(sender_domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(creation, datetime):
            created_at = creation
            # Normalize naive datetimes to UTC to keep subtraction timezone-safe.
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - created_at).days
            if age_days < 90:
                click_probability += 0.25
                indicators.append(f"new_domain_age:{age_days}d")
    except Exception:
        pass  # WHOIS lookup unavailable or timed out — skip silently

    if legitimacy.level == "strong" and legitimacy.credential_bait_hits == 0:
        click_probability -= 0.15
    elif legitimacy.level == "moderate" and legitimacy.credential_bait_hits == 0:
        click_probability -= 0.08

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
        ml_risk = ml_prediction.get("risk_score", 0.0)
        # Fuse outputs allowing XGBoost explicit dominance given exact deterministic mapping
        fused_risk = (0.85 * ml_risk) + (0.15 * heuristic_result["risk_score"])
        final_risk = _clamp(max(fused_risk, ml_risk))
        final_confidence = _clamp(max(heuristic_result["confidence"], ml_prediction.get("confidence", 0.0)))
        final_indicators = list(set(heuristic_result["indicators"] + ml_prediction.get("indicators", [])))[:20]
    else:
        final_risk = heuristic_result["risk_score"]
        final_confidence = heuristic_result["confidence"]
        final_indicators = heuristic_result["indicators"]

    if legitimacy.level in {"strong", "moderate"} and legitimacy.credential_bait_hits == 0:
        cap = 0.58 if legitimacy.level == "strong" else 0.68
        final_risk = _clamp(min(final_risk, cap))
        final_indicators.append(f"transactional_legitimacy_profile:{legitimacy.level}")
        final_indicators.extend(legitimacy.indicators[:2])

    result = {
        "agent_name": "user_behavior_agent",
        "risk_score": final_risk,
        "confidence": final_confidence,
        "indicators": final_indicators,
    }

    logger.info("Analysis complete", risk_score=result["risk_score"])
    return result
