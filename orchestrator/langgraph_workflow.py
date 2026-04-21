"""LangGraph-based orchestrator workflow for threat decisioning."""

from __future__ import annotations

from typing import Any, Callable

from langgraph.graph import END, StateGraph

from email_security.garuda_integration.bridge import trigger_garuda_investigation
from email_security.orchestrator.counterfactual_engine import calculate_counterfactual, threshold_for_verdict
from email_security.orchestrator.llm_reasoner import generate_reasoning
from email_security.orchestrator.scoring_engine import calculate_threat_score
from email_security.orchestrator.storyline_engine import generate_storyline
from email_security.orchestrator.threat_correlation import correlate_threats
from email_security.orchestrator.langgraph_state import OrchestratorState
from email_security.services.logging_service import get_service_logger

logger = get_service_logger("langgraph_orchestrator")


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


def _has_spam_campaign_pattern(agent_results: list[dict[str, Any]]) -> bool:
    content = next((item for item in agent_results if str(item.get("agent_name")) == "content_agent"), None)
    header = next((item for item in agent_results if str(item.get("agent_name")) == "header_agent"), None)
    if not content:
        return False

    content_risk = float(content.get("risk_score") or 0.0)
    content_indicators = [str(item).lower() for item in (content.get("indicators") or [])]
    has_spam_content = any(ind.startswith("ml_slm_label:spam") for ind in content_indicators) or any(
        ind.startswith("spam_marketing_signals:") for ind in content_indicators
    )
    if not has_spam_content or content_risk < 0.55:
        return False

    header_indicators = [str(item).lower() for item in ((header or {}).get("indicators") or [])]
    has_delivery_anomaly = any(
        token in indicator
        for indicator in header_indicators
        for token in ("authentication_results_missing", "short_smtp_trace", "no_auth_headers_with_domain")
    )
    return has_delivery_anomaly


def _has_uncertain_conflict_pattern(agent_results: list[dict[str, Any]], normalized_score: float) -> bool:
    """Identify evidence disagreement strong enough to force manual review.

    Trigger only below blocking threshold to avoid overriding clear malicious outcomes.
    """
    if normalized_score >= 0.4:
        return False

    informative = [
        item
        for item in agent_results
        if float(item.get("confidence") or 0.0) >= 0.7
    ]
    if len(informative) < 3:
        return False

    scores = [float(item.get("risk_score") or 0.0) for item in informative]
    high_votes = sum(1 for score in scores if score >= 0.65)
    low_votes = sum(1 for score in scores if score <= 0.2)
    spread = max(scores) - min(scores)

    return high_votes >= 1 and low_votes >= 2 and spread >= 0.45


class LangGraphOrchestrator:
    """Builds and executes graph-driven orchestration for final threat decisions."""

    def __init__(
        self,
        save_report: Callable[[str, dict[str, Any]], None],
        execute_actions: Callable[[dict[str, Any]], None],
    ):
        self._save_report = save_report
        self._execute_actions = execute_actions
        self._graph = self._build_graph()

    def _build_graph(self):
        graph = StateGraph(OrchestratorState)

        graph.add_node("score", self._score_node)
        graph.add_node("correlate", self._correlate_node)
        graph.add_node("decide", self._decide_node)
        graph.add_node("reason", self._reason_node)
        graph.add_node("garuda", self._garuda_node)
        graph.add_node("persist", self._persist_node)
        graph.add_node("act", self._act_node)
        graph.add_node("finalize", self._finalize_node)

        graph.set_entry_point("score")
        graph.add_edge("score", "correlate")
        graph.add_edge("correlate", "decide")
        graph.add_edge("decide", "reason")
        graph.add_conditional_edges(
            "reason",
            self._needs_garuda,
            {
                "garuda": "garuda",
                "persist": "persist",
            },
        )
        graph.add_edge("garuda", "persist")
        graph.add_edge("persist", "act")
        graph.add_edge("act", "finalize")
        graph.add_edge("finalize", END)

        return graph.compile()

    def run(self, initial_state: OrchestratorState) -> OrchestratorState:
        return self._graph.invoke(initial_state)

    def _score_node(self, state: OrchestratorState) -> OrchestratorState:
        results = state.get("agent_results", [])
        score_data = calculate_threat_score(results)
        logger.info("LangGraph node complete", node="score", analysis_id=state.get("analysis_id"))
        return {"score_data": score_data}

    def _correlate_node(self, state: OrchestratorState) -> OrchestratorState:
        results = state.get("agent_results", [])
        correlation = correlate_threats(results)
        logger.info("LangGraph node complete", node="correlate", analysis_id=state.get("analysis_id"))
        return {"correlation": correlation}

    def _decide_node(self, state: OrchestratorState) -> OrchestratorState:
        score_data = state.get("score_data", {})
        correlation = state.get("correlation", {})
        agent_results = state.get("agent_results", [])

        overall = float(score_data.get("overall_score", 0.0))
        corr_score = float(correlation.get("correlation_score", 0.0))
        normalized_score = min(1.0, overall + (0.2 * corr_score))

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
        decision_notes: list[str] = []

        if (
            verdict == "suspicious"
            and _has_strong_transactional_legitimacy(agent_results)
            and not _has_hard_malicious_signal(agent_results)
        ):
            verdict = "likely_safe"
            actions = ["deliver_with_banner"]
            decision_notes.append("downgraded_by_transactional_legitimacy")

        if (
            verdict == "likely_safe"
            and _has_spam_campaign_pattern(agent_results)
            and not _has_strong_transactional_legitimacy(agent_results)
        ):
            verdict = "suspicious"
            actions = ["manual_review", "soc_alert"]
            normalized_score = max(normalized_score, 0.42)
            decision_notes.append("escalated_by_spam_campaign_pattern")

        if verdict == "likely_safe" and _has_uncertain_conflict_pattern(agent_results, normalized_score):
            verdict = "suspicious"
            actions = ["manual_review"]
            normalized_score = max(normalized_score, 0.4)
            decision_notes.append("escalated_by_uncertain_conflict_guardrail")

        logger.info("LangGraph node complete", node="decide", analysis_id=state.get("analysis_id"))
        return {
            "normalized_score": round(normalized_score, 4),
            "overall_risk_score": round(normalized_score, 4),
            "verdict": verdict,
            "recommended_actions": actions,
            "threat_level": score_data.get("threat_level", "unknown"),
            "decision_notes": decision_notes,
        }

    def _reason_node(self, state: OrchestratorState) -> OrchestratorState:
        agent_results = state.get("agent_results", [])
        overall_score = float(state.get("normalized_score", 0.0))
        correlation = state.get("correlation", {})
        verdict = state.get("verdict", "unknown")
        actions = state.get("recommended_actions", [])

        threshold = threshold_for_verdict(verdict)
        if threshold is not None and agent_results:
            counterfactual = calculate_counterfactual(
                agent_results=agent_results,
                correlation=correlation,
                current_normalized_score=overall_score,
                threshold=threshold,
            )
        else:
            counterfactual = {"is_counterfactual": False, "reason": "no_blocking_boundary"}

        storyline = generate_storyline(agent_results, verdict, actions) if agent_results else []

        explanation = generate_reasoning(
            agent_results,
            overall_score,
            counterfactual=counterfactual
        )

        logger.info("LangGraph node complete", node="reason", analysis_id=state.get("analysis_id"))
        return {
            "llm_explanation": explanation,
            "counterfactual_result": counterfactual,
            "threat_storyline": storyline,
        }

    def _needs_garuda(self, state: OrchestratorState) -> str:
        return "garuda" if float(state.get("overall_risk_score", 0.0)) > 0.7 else "persist"

    def _garuda_node(self, state: OrchestratorState) -> OrchestratorState:
        decision = self._assemble_decision(state)
        feedback = trigger_garuda_investigation(decision)
        logger.info("LangGraph node complete", node="garuda", analysis_id=state.get("analysis_id"))
        return {"garuda_feedback": feedback}

    def _persist_node(self, state: OrchestratorState) -> OrchestratorState:
        analysis_id = str(state.get("analysis_id", ""))
        decision = self._assemble_decision(state)
        self._save_report(analysis_id, decision)
        logger.info("LangGraph node complete", node="persist", analysis_id=analysis_id)
        return {
            "decision": decision,
            "persistence_status": "saved",
        }

    def _act_node(self, state: OrchestratorState) -> OrchestratorState:
        decision = state.get("decision") or self._assemble_decision(state)
        self._execute_actions(decision)
        logger.info("LangGraph node complete", node="act", analysis_id=state.get("analysis_id"))
        return {"action_status": "dispatched"}

    def _finalize_node(self, state: OrchestratorState) -> OrchestratorState:
        decision = state.get("decision") or self._assemble_decision(state)
        logger.info("LangGraph node complete", node="finalize", analysis_id=state.get("analysis_id"))
        return {"decision": decision}

    def _assemble_decision(self, state: OrchestratorState) -> dict[str, Any]:
        decision = {
            "analysis_id": state.get("analysis_id"),
            "overall_risk_score": float(state.get("overall_risk_score", 0.0)),
            "verdict": state.get("verdict", "unknown"),
            "recommended_actions": state.get("recommended_actions", []),
            "threat_level": state.get("threat_level", "unknown"),
            "llm_explanation": state.get("llm_explanation", ""),
            "agent_results": state.get("agent_results", []),
            "correlation": state.get("correlation", {}),
            "score_data": state.get("score_data", {}),
            "finalization_reason": state.get("finalization_reason", "complete"),
            "received_agents": state.get("received_agents", []),
            "missing_agents": state.get("missing_agents", []),
            "is_partial": bool(state.get("is_partial", False)),
            "threat_storyline": state.get("threat_storyline", []),
            "counterfactual_result": state.get("counterfactual_result", None),
            "decision_notes": state.get("decision_notes", []),
        }
        if state.get("garuda_feedback"):
            decision["garuda_feedback"] = state.get("garuda_feedback")
        return decision
