"""
Decision Engine for the Agentic Email Security System.

LEGACY CONVENIENCE MODULE — The production runtime uses the LangGraph
orchestrator workflow (langgraph_workflow.py) which encapsulates scoring,
correlation, counterfactual, reasoning, storyline, and action dispatch in
a unified graph.

This module is retained as a convenience wrapper for direct testing and
external callers that want a single-call decision without standing up the
full LangGraph pipeline.
"""

from typing import Any

from email_security.orchestrator.llm_reasoner import generate_reasoning
from email_security.orchestrator.scoring_engine import calculate_threat_score
from email_security.orchestrator.threat_correlation import correlate_threats
from email_security.orchestrator.counterfactual_engine import calculate_counterfactual, threshold_for_verdict
from email_security.orchestrator.storyline_engine import generate_storyline
from email_security.services.logging_service import get_service_logger

logger = get_service_logger("decision_engine")


def _contains_indicator(agent: dict[str, Any], token: str) -> bool:
    indicators = [str(item).lower() for item in (agent.get("indicators") or [])]
    return any(token in item for item in indicators)


def _has_hard_malicious_signal(agent_results: list[dict[str, Any]]) -> bool:
    for item in agent_results:
        name = str(item.get("agent_name") or "")
        risk = float(item.get("risk_score") or 0.0)

        if name in {"attachment_agent", "sandbox_agent"} and risk >= 0.75:
            return True
        if name == "threat_intel_agent" and risk >= 0.6:
            return True
        if name == "header_agent" and (
            _contains_indicator(item, "lookalike_domain")
            or _contains_indicator(item, "reply_to_domain_mismatch")
            or _contains_indicator(item, "dmarc_failed")
        ):
            return True
    return False


def _has_strong_transactional_legitimacy(agent_results: list[dict[str, Any]]) -> bool:
    strong_votes = 0
    for item in agent_results:
        if _contains_indicator(item, "transactional_legitimacy_profile:strong"):
            strong_votes += 1
    return strong_votes >= 2


def make_decision(agent_results: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Aggregate agent results and produce a final threat decision.

    This is a standalone convenience function that mirrors the LangGraph
    workflow logic.  For production use, prefer :class:`LangGraphOrchestrator`.

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

    if (
        verdict == "suspicious"
        and _has_strong_transactional_legitimacy(agent_results)
        and not _has_hard_malicious_signal(agent_results)
    ):
        verdict = "likely_safe"
        actions = ["deliver_with_banner"]

    # Counterfactual analysis
    threshold = threshold_for_verdict(verdict)
    if threshold is not None:
        counterfactual = calculate_counterfactual(
            agent_results=agent_results,
            correlation=correlation,
            current_normalized_score=normalized_score,
            threshold=threshold,
        )
    else:
        counterfactual = {"is_counterfactual": False, "reason": "no_blocking_boundary"}

    # LLM reasoning (falls back to deterministic if Azure OpenAI is unavailable)
    llm_explanation = generate_reasoning(agent_results, normalized_score, counterfactual)

    # Threat storyline
    storyline = generate_storyline(agent_results, verdict, actions)

    decision = {
        "overall_risk_score": round(normalized_score, 4),
        "verdict": verdict,
        "recommended_actions": actions,
        "threat_level": score_data["threat_level"],
        "correlation": correlation,
        "counterfactual_result": counterfactual,
        "threat_storyline": storyline,
        "llm_explanation": llm_explanation,
        "agent_results": agent_results,
    }

    logger.info("Decision made", verdict=decision["verdict"])
    return decision
