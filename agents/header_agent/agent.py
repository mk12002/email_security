"""Header analysis agent with auth checks, look-alike domain detection, and ML anomaly scoring."""

from __future__ import annotations

from typing import Any

from Levenshtein import distance as levenshtein_distance

from email_security.agents.header_agent.feature_extractor import extract_features
from email_security.agents.header_agent.inference import predict
from email_security.agents.header_agent.model_loader import load_model
from email_security.agents.ml_runtime import clamp as _clamp
from email_security.services.logging_service import get_agent_logger

logger = get_agent_logger("header_agent")

TRUSTED_DOMAINS = {
    "microsoft.com",
    "google.com",
    "paypal.com",
    "amazon.com",
    "apple.com",
}

_model_cache = None

def _get_model():
    global _model_cache
    if _model_cache is None:
        try:
            _model_cache = load_model()
        except Exception:
            _model_cache = False  # Use False to distinguish between None (not loaded) and False (failed to load)
    return _model_cache if _model_cache is not False else None



def _domain_from_sender(sender: str) -> str:
    if "@" not in sender:
        return ""
    return sender.split("@")[-1].strip().lower()


def _auth_all_pass(auth: str) -> bool:
    auth_l = (auth or "").lower()
    return (
        "spf=pass" in auth_l
        and "dkim=pass" in auth_l
        and "dmarc=pass" in auth_l
    )


def analyze(data: dict[str, Any]) -> dict[str, Any]:
    logger.info("Starting analysis", agent="header_agent")
    headers = data.get("headers", {}) or {}
    auth = (headers.get("authentication_results") or "").lower()
    sender = headers.get("sender", "")
    reply_to = headers.get("reply_to", "") or ""
    sender_domain = _domain_from_sender(sender)
    reply_to_domain = _domain_from_sender(reply_to)
    received = headers.get("received", []) or []
    auth_all_pass = _auth_all_pass(auth)

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

        # Authenticated single-hop traffic can still be suspicious in SOC triage.
        # Keep these events in review band rather than auto-safe.
        if auth_all_pass:
            risk += 0.3
            indicators.append("authenticated_single_hop_anomaly")

    if reply_to_domain and sender_domain and reply_to_domain != sender_domain:
        risk += 0.24
        indicators.append("reply_to_domain_mismatch")

        if auth_all_pass:
            risk += 0.12
            indicators.append("authenticated_reply_to_anomaly")

    heuristic_confidence = _clamp(0.65 + min(0.25, len(indicators) * 0.05))

    # 2. ML Prediction
    features = extract_features(data)
    ml_result = predict(features, _get_model())

    if ml_result.get("confidence", 0.0) > 0.0:
        # Weighted fusion: 60% ML, 40% heuristic (consistent with other agents)
        final_risk = _clamp((0.6 * ml_result["risk_score"]) + (0.4 * risk))
        final_confidence = _clamp(max(heuristic_confidence, ml_result.get("confidence", 0.0)))
        indicators.extend(ml_result.get("indicators", []))
    else:
        final_risk = _clamp(risk)
        final_confidence = heuristic_confidence

    # SOC guardrail: ensure authenticated-but-anomalous headers stay reviewable.
    if (
        "authenticated_single_hop_anomaly" in indicators
        or "authenticated_reply_to_anomaly" in indicators
    ):
        final_risk = _clamp(max(final_risk, 0.42))

    result = {
        "agent_name": "header_agent",
        "risk_score": final_risk,
        "confidence": final_confidence,
        "indicators": indicators[:20],
    }
    logger.info("Analysis complete", risk_score=result["risk_score"], used_ml=ml_result.get("confidence", 0.0) > 0)
    return result
