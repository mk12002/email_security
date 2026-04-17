"""Tests for LangGraph-based orchestrator workflow."""

from __future__ import annotations

from email_security.orchestrator.langgraph_workflow import LangGraphOrchestrator


def test_langgraph_orchestrator_produces_decision() -> None:
    persisted: dict[str, object] = {}

    def _save(analysis_id: str, decision: dict[str, object]) -> None:
        persisted["analysis_id"] = analysis_id
        persisted["decision"] = decision

    def _act(_decision: dict[str, object]) -> None:
        return None

    graph = LangGraphOrchestrator(save_report=_save, execute_actions=_act)
    state = {
        "analysis_id": "analysis-123",
        "agent_results": [
            {"agent_name": "content_agent", "risk_score": 0.2, "confidence": 0.8, "indicators": ["urgency"]},
            {"agent_name": "header_agent", "risk_score": 0.1, "confidence": 0.7, "indicators": ["spf_failed"]},
        ],
        "finalization_reason": "partial_timeout",
        "received_agents": ["content_agent", "header_agent"],
        "missing_agents": ["url_agent"],
        "is_partial": True,
    }

    final_state = graph.run(state)
    decision = final_state.get("decision", {})

    assert decision.get("analysis_id") == "analysis-123"
    assert "overall_risk_score" in decision
    assert "verdict" in decision
    assert "recommended_actions" in decision
    assert decision.get("finalization_reason") == "partial_timeout"
    assert decision.get("is_partial") is True
    assert persisted.get("analysis_id") == "analysis-123"


def test_langgraph_decide_node_downgrades_transactional_false_positive() -> None:
    graph = LangGraphOrchestrator(save_report=lambda _id, _d: None, execute_actions=lambda _d: None)

    state = {
        "score_data": {"overall_score": 0.48, "threat_level": "medium"},
        "correlation": {"correlation_score": 0.1},
        "agent_results": [
            {
                "agent_name": "content_agent",
                "risk_score": 0.62,
                "confidence": 0.91,
                "indicators": ["transactional_legitimacy_profile:strong"],
            },
            {
                "agent_name": "url_agent",
                "risk_score": 0.63,
                "confidence": 0.86,
                "indicators": ["transactional_legitimacy_profile:strong"],
            },
            {
                "agent_name": "user_behavior_agent",
                "risk_score": 0.58,
                "confidence": 0.85,
                "indicators": ["transactional_legitimacy_profile:strong"],
            },
            {
                "agent_name": "attachment_agent",
                "risk_score": 0.0,
                "confidence": 0.8,
                "indicators": ["no_attachments"],
            },
        ],
    }

    decision = graph._decide_node(state)
    assert decision["verdict"] == "likely_safe"
    assert decision["recommended_actions"] == ["deliver_with_banner"]


def test_langgraph_decide_node_keeps_suspicious_with_hard_signal() -> None:
    graph = LangGraphOrchestrator(save_report=lambda _id, _d: None, execute_actions=lambda _d: None)

    state = {
        "score_data": {"overall_score": 0.48, "threat_level": "medium"},
        "correlation": {"correlation_score": 0.1},
        "agent_results": [
            {
                "agent_name": "content_agent",
                "risk_score": 0.62,
                "confidence": 0.91,
                "indicators": ["transactional_legitimacy_profile:strong"],
            },
            {
                "agent_name": "url_agent",
                "risk_score": 0.63,
                "confidence": 0.86,
                "indicators": ["transactional_legitimacy_profile:strong"],
            },
            {
                "agent_name": "attachment_agent",
                "risk_score": 0.92,
                "confidence": 0.8,
                "indicators": ["suspicious_extension:invoice.pdf.exe"],
            },
        ],
    }

    decision = graph._decide_node(state)
    assert decision["verdict"] == "suspicious"
    assert decision["recommended_actions"] == ["manual_review", "soc_alert"]
