"""
Decision Engine for the Agentic Email Security System.

Aggregates outputs from all agents and makes the final threat determination.
"""

from typing import Any

from email_security.orchestrator.llm_reasoner import generate_reasoning
from email_security.orchestrator.scoring_engine import calculate_threat_score
from email_security.orchestrator.threat_correlation import correlate_threats
from email_security.services.logging_service import get_service_logger

logger = get_service_logger("decision_engine")


def make_decision(agent_results: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Aggregate agent results and produce a final threat decision.

    Args:
        agent_results: List of standardized agent result dictionaries.

    Returns:
        Final decision with overall risk score, verdict, and recommended actions.
    """
    logger.info("Making decision", agent_count=len(agent_results))

    score_data = calculate_threat_score(agent_results)
    correlation = correlate_threats(agent_results)
    normalized_score = min(1.0, score_data["overall_score"] + (0.2 * correlation["correlation_score"]))

    if normalized_score >= 0.8:
        verdict = "malicious"
        actions = ["quarantine", "block_sender", "trigger_garuda"]
    elif normalized_score >= 0.6:
        verdict = "high_risk"
        actions = ["quarantine", "soc_alert", "trigger_garuda"]
    elif normalized_score >= 0.4:
        verdict = "suspicious"
        actions = ["manual_review", "soc_alert"]
    else:
        verdict = "likely_safe"
        actions = ["deliver_with_banner"]

    decision = {
        "overall_risk_score": round(normalized_score, 4),
        "verdict": verdict,
        "recommended_actions": actions,
        "threat_level": score_data["threat_level"],
        "correlation": correlation,
        "llm_explanation": generate_reasoning(agent_results, normalized_score),
        "agent_results": agent_results,
    }

    logger.info("Decision made", verdict=decision["verdict"])
    return decision
