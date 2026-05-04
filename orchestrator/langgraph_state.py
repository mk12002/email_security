"""Shared LangGraph state schema for orchestrator decision flow."""

from __future__ import annotations

from typing import Any, TypedDict


class OrchestratorState(TypedDict, total=False):
    # Inputs
    analysis_id: str
    agent_results: list[dict[str, Any]]
    finalization_reason: str
    received_agents: list[str]
    missing_agents: list[str]
    is_partial: bool

    # Email identity (for Graph action layer)
    user_principal_name: str
    internet_message_id: str
    graph_message_id: str

    # Derived scoring/correlation
    score_data: dict[str, Any]
    correlation: dict[str, Any]
    normalized_score: float
    counterfactual_result: dict[str, Any]

    # Decision outputs
    overall_risk_score: float
    verdict: str
    recommended_actions: list[str]
    threat_level: str
    llm_explanation: str
    threat_storyline: list[dict[str, Any]]
    decision_notes: list[str]

    # Side-effect outputs
    garuda_feedback: dict[str, Any]
    persistence_status: str
    action_status: str

    # Final envelope for persistence/reporting
    decision: dict[str, Any]
