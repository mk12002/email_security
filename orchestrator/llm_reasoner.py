"""
LLM reasoner for final risk explanation (Azure OpenAI with local fallback).
"""

from __future__ import annotations

from typing import Any

from openai import AzureOpenAI

from email_security.configs.settings import settings
from email_security.services.logging_service import get_service_logger

logger = get_service_logger("llm_reasoner")


def _fallback_explanation(agent_results: list[dict[str, Any]], score: float, counterfactual: dict[str, Any] | None = None) -> str:
    top = sorted(agent_results, key=lambda entry: entry.get("risk_score", 0.0), reverse=True)[:3]
    highlights = ", ".join(
        f"{entry.get('agent_name')}={entry.get('risk_score', 0.0):.2f}" for entry in top
    )
    base = (
        f"Final score {score:.2f}. Top contributing agents: {highlights}. "
        "This verdict is generated using deterministic weighting because Azure OpenAI is unavailable."
    )
    if counterfactual and counterfactual.get("is_counterfactual"):
        agents = ", ".join(counterfactual.get("agents_altered", []))
        base += f" However, if {agents} were safe, the score would drop to {counterfactual.get('new_normalized_score')}."
    return base


def generate_reasoning(
    agent_results: list[dict[str, Any]], 
    normalized_score: float,
    counterfactual: dict[str, Any] | None = None
) -> str:
    if not (
        settings.azure_openai_endpoint
        and settings.azure_openai_api_key
        and settings.azure_openai_deployment
    ):
        return _fallback_explanation(agent_results, normalized_score, counterfactual)

    try:
        client = AzureOpenAI(
            api_key=settings.azure_openai_api_key,
            azure_endpoint=settings.azure_openai_endpoint,
            api_version=settings.azure_openai_api_version,
        )
        
        prompt = (
            "You are SOC reasoning engine. "
            "Given the agent outputs, explain the likely attack scenario, confidence, and final score. "
            "Keep under 120 words.\n"
            f"Agent outputs: {agent_results}\n"
            f"Preliminary score: {normalized_score:.4f}\n"
        )
        
        if counterfactual and counterfactual.get("is_counterfactual"):
            agents = ", ".join(counterfactual.get("agents_altered", []))
            new_score = counterfactual.get("new_normalized_score", 0)
            prompt += (
                f"\nIMPORTANT COUNTERFACTUAL BOUNDARY: This email was blocked. "
                f"However, we calculated that if the findings from [{agents}] were neutralized "
                f"to be completely safe, the final score would drop to {new_score} and the email would have been delivered. "
                f"Be sure to explicitly mention this counterfactual in your explanation so the human analyst knows exactly what triggered the block."
            )
        completion = client.chat.completions.create(
            model=settings.azure_openai_deployment,
            messages=[
                {"role": "system", "content": "You are a cybersecurity triage analyst."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.1,
        )
        content = completion.choices[0].message.content
        return content or _fallback_explanation(agent_results, normalized_score, counterfactual)
    except Exception as exc:
        logger.warning("Azure OpenAI reasoning failed", error=str(exc))
        return _fallback_explanation(agent_results, normalized_score, counterfactual)
