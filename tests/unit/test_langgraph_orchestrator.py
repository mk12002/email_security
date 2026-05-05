"""Tests for LangGraph-based orchestrator workflow."""

from __future__ import annotations

from email_security.src.orchestrator.langgraph_workflow import LangGraphOrchestrator


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


def test_langgraph_reason_node_emits_structured_explainability() -> None:
    graph = LangGraphOrchestrator(save_report=lambda _id, _d: None, execute_actions=lambda _d: None)

    state = {
        "analysis_id": "analysis-structured-1",
        "normalized_score": 0.67,
        "correlation": {"correlation_score": 0.3},
        "verdict": "high_risk",
        "recommended_actions": ["quarantine", "soc_alert", "trigger_garuda"],
        "agent_results": [
            {
                "agent_name": "attachment_agent",
                "risk_score": 0.92,
                "confidence": 0.88,
                "indicators": ["double_extension", "high_entropy"],
            },
            {
                "agent_name": "header_agent",
                "risk_score": 0.45,
                "confidence": 0.75,
                "indicators": ["reply_to_domain_mismatch"],
            },
        ],
    }

    reason = graph._reason_node(state)

    assert isinstance(reason.get("llm_explanation"), str)
    assert isinstance(reason.get("counterfactual_result"), dict)
    assert isinstance(reason.get("threat_storyline"), list)
    assert reason["counterfactual_result"].get("threshold") == 0.6
    assert any(event.get("phase") == "Containment" for event in reason["threat_storyline"])


def test_langgraph_decide_node_escalates_spam_campaign_pattern() -> None:
    graph = LangGraphOrchestrator(save_report=lambda _id, _d: None, execute_actions=lambda _d: None)

    state = {
        "score_data": {"overall_score": 0.19, "threat_level": "safe"},
        "correlation": {"correlation_score": 0.0},
        "agent_results": [
            {
                "agent_name": "content_agent",
                "risk_score": 0.68,
                "confidence": 0.9,
                "indicators": [
                    "spam_marketing_signals:investment properties,pay cash",
                    "ml_slm_label:Spam",
                ],
            },
            {
                "agent_name": "header_agent",
                "risk_score": 0.43,
                "confidence": 0.8,
                "indicators": [
                    "missing_data:authentication_results_missing",
                    "no_auth_headers_with_domain",
                ],
            },
            {
                "agent_name": "user_behavior_agent",
                "risk_score": 0.06,
                "confidence": 0.8,
                "indicators": ["unfamiliar_sender_domain"],
            },
        ],
    }

    decision = graph._decide_node(state)
    assert decision["verdict"] == "suspicious"
    assert decision["recommended_actions"] == ["manual_review", "soc_alert"]
    assert float(decision["normalized_score"]) >= 0.42


def test_langgraph_decide_node_does_not_escalate_when_transactional_strong() -> None:
    graph = LangGraphOrchestrator(save_report=lambda _id, _d: None, execute_actions=lambda _d: None)

    state = {
        "score_data": {"overall_score": 0.33, "threat_level": "medium"},
        "correlation": {"correlation_score": 0.0},
        "agent_results": [
            {
                "agent_name": "content_agent",
                "risk_score": 0.62,
                "confidence": 0.92,
                "indicators": [
                    "financial_signals:payment",
                    "transactional_legitimacy_profile:strong",
                ],
            },
            {
                "agent_name": "url_agent",
                "risk_score": 0.44,
                "confidence": 0.85,
                "indicators": ["transactional_legitimacy_profile:strong"],
            },
            {
                "agent_name": "user_behavior_agent",
                "risk_score": 0.58,
                "confidence": 0.85,
                "indicators": ["transactional_legitimacy_profile:strong"],
            },
        ],
    }

    decision = graph._decide_node(state)
    assert decision["verdict"] == "likely_safe"


def test_langgraph_decide_node_escalates_uncertain_conflict_to_manual_review() -> None:
    graph = LangGraphOrchestrator(save_report=lambda _id, _d: None, execute_actions=lambda _d: None)

    state = {
        "score_data": {"overall_score": 0.27, "threat_level": "low"},
        "correlation": {"correlation_score": 0.0},
        "agent_results": [
            {
                "agent_name": "content_agent",
                "risk_score": 0.74,
                "confidence": 0.93,
                "indicators": ["urgent_payment_language"],
            },
            {
                "agent_name": "url_agent",
                "risk_score": 0.08,
                "confidence": 0.82,
                "indicators": ["global_allowlist_prior_applied"],
            },
            {
                "agent_name": "header_agent",
                "risk_score": 0.12,
                "confidence": 0.89,
                "indicators": ["auth_all_pass"],
            },
            {
                "agent_name": "user_behavior_agent",
                "risk_score": 0.11,
                "confidence": 0.86,
                "indicators": ["historically_known_sender"],
            },
        ],
    }

    decision = graph._decide_node(state)
    assert decision["verdict"] == "suspicious"
    assert decision["recommended_actions"] == ["manual_review"]
    assert "escalated_by_uncertain_conflict_guardrail" in decision["decision_notes"]


def test_langgraph_decide_node_does_not_escalate_uncertain_conflict_when_already_high() -> None:
    graph = LangGraphOrchestrator(save_report=lambda _id, _d: None, execute_actions=lambda _d: None)

    state = {
        "score_data": {"overall_score": 0.63, "threat_level": "high"},
        "correlation": {"correlation_score": 0.1},
        "agent_results": [
            {
                "agent_name": "content_agent",
                "risk_score": 0.75,
                "confidence": 0.93,
                "indicators": ["urgent_payment_language"],
            },
            {
                "agent_name": "url_agent",
                "risk_score": 0.08,
                "confidence": 0.82,
                "indicators": ["global_allowlist_prior_applied"],
            },
            {
                "agent_name": "header_agent",
                "risk_score": 0.12,
                "confidence": 0.89,
                "indicators": ["auth_all_pass"],
            },
        ],
    }

    decision = graph._decide_node(state)
    assert decision["verdict"] in {"high_risk", "malicious"}
    assert "escalated_by_uncertain_conflict_guardrail" not in decision["decision_notes"]
