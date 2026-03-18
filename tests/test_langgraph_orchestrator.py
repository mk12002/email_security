"""Tests for LangGraph-based orchestrator workflow."""

from __future__ import annotations

from orchestrator.langgraph_workflow import LangGraphOrchestrator


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
