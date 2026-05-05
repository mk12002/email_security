"""
LLM reasoner for final risk explanation (Azure OpenAI with local fallback).
"""

from __future__ import annotations

from typing import Any

import functools
from openai import AzureOpenAI

from email_security.src.configs.settings import settings
from email_security.src.services.logging_service import get_service_logger

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


@functools.lru_cache(maxsize=2000)
def _cached_azure_call(system_prompt: str, user_prompt: str) -> str | None:
    try:
        client = AzureOpenAI(
            api_key=settings.azure_openai_api_key,
            azure_endpoint=settings.azure_openai_endpoint,
            api_version=settings.azure_openai_api_version,
        )
        completion = client.chat.completions.create(
            model=settings.azure_openai_deployment,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.1,
        )
        return completion.choices[0].message.content
    except Exception as exc:
        logger.warning("Azure OpenAI reasoning failed", error=str(exc))
        return None


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
    
    content = _cached_azure_call("You are a cybersecurity triage analyst.", prompt)
    return content or _fallback_explanation(agent_results, normalized_score, counterfactual)


def explain_counterfactual(counterfactual: dict[str, Any]) -> str:
    if not counterfactual or not counterfactual.get("is_counterfactual"):
        return "No counterfactual scenario was applicable for this verdict."
    
    if not (settings.azure_openai_endpoint and settings.azure_openai_api_key and settings.azure_openai_deployment):
        return f"Raw Counterfactual: {counterfactual}"
        
    agents = ", ".join(counterfactual.get("agents_altered", []))
    new_score = counterfactual.get("new_normalized_score")
    prompt = (
        f"Explain the following counterfactual logic in 1-2 clear, human-readable sentences for a SOC analyst.\n"
        f"Data: We calculated that if the findings from [{agents}] were completely safe, the final risk score would drop to {new_score} "
        f"and the email would have been delivered.\nMake it sound professional and explanatory."
    )
    
    content = _cached_azure_call("You are a cybersecurity triage analyst.", prompt)
    return content or "Counterfactual generated."


def explain_storyline(storyline: list[dict[str, Any]]) -> str:
    if not storyline:
        return "No obvious threat storyline detected."
        
    if not (settings.azure_openai_endpoint and settings.azure_openai_api_key and settings.azure_openai_deployment):
        return f"Raw Storyline: {storyline}"
        
    prompt = (
        "You are a SOC reasoning engine. Convert the following list of attack phases into a beautiful, chronological "
        "Markdown-formatted threat narrative for an analyst to read. Use clear spacing.\n"
        "CRITICAL: You MUST include a Mermaid.js directional graph (`graph TD`) mapping the attack progression conceptually. "
        "Place it inside a ```mermaid code block along with the text narrative.\n"
        f"Raw phases: {storyline}"
    )
    
    content = _cached_azure_call("You are a cybersecurity triage analyst configuring markdown narratives with diagrams.", prompt)
    return content or "Storyline generated."
