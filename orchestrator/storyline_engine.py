"""
Threat Storyline Engine for translating disconnected agent indicators into
a chronological narrative (Delivery -> Lure -> Weaponization -> Result).
"""

from typing import Any
from email_security.services.logging_service import get_service_logger

logger = get_service_logger("storyline_engine")


def _severity_from_risk(risk_score: float) -> str:
    value = float(risk_score or 0.0)
    if value >= 0.8:
        return "high"
    if value >= 0.5:
        return "medium"
    return "low"


def _aggregate_event_stats(items: list[dict[str, Any]]) -> tuple[str, float]:
    if not items:
        return "low", 0.0
    max_risk = max(float(item.get("risk_score", 0.0) or 0.0) for item in items)
    avg_conf = sum(float(item.get("confidence", 0.0) or 0.0) for item in items) / len(items)
    return _severity_from_risk(max_risk), round(max(0.0, min(1.0, avg_conf)), 4)


def _build_indicator_objects(items: list[dict[str, Any]], tactic: str) -> list[dict[str, Any]]:
    mapped: list[dict[str, Any]] = []
    for entry in items:
        agent_name = str(entry.get("agent_name", "unknown_agent"))
        confidence = round(max(0.0, min(1.0, float(entry.get("confidence", 0.0) or 0.0))), 4)
        severity = _severity_from_risk(float(entry.get("risk_score", 0.0) or 0.0))
        for indicator in entry.get("indicators", []) or []:
            mapped.append(
                {
                    "value": f"[{agent_name}] {indicator}",
                    "severity": severity,
                    "confidence": confidence,
                    "tactic": tactic,
                }
            )
    return mapped


def generate_storyline(
    agent_results: list[dict[str, Any]], verdict: str, recommended_actions: list[str]
) -> list[dict[str, Any]]:
    """
    Given the list of agent evaluations, map them to chronological attack phases.
    """
    logger.info("Generating threat storyline timeline")
    storyline = []

    # Map agent names to logical phases
    delivery_agents = {"header_agent", "threat_intel_agent"}
    lure_agents = {"content_agent", "user_behavior_agent"}
    weapon_agents = {"url_agent", "attachment_agent", "sandbox_agent"}

    delivery_items: list[dict[str, Any]] = []
    lure_items: list[dict[str, Any]] = []
    weapon_items: list[dict[str, Any]] = []

    for result in agent_results:
        agent_name = result.get("agent_name", "")
        # Only extract indicators if the agent flagged some risk or explicitly found things
        indicators = result.get("indicators", [])
        if not indicators:
            continue

        if agent_name in delivery_agents:
            delivery_items.append(result)
        elif agent_name in lure_agents:
            lure_items.append(result)
        elif agent_name in weapon_agents:
            weapon_items.append(result)
        else:
            # Fallback for unknown agents
            weapon_items.append(result)

    # 1. Delivery Phase
    if delivery_items:
        severity, confidence = _aggregate_event_stats(delivery_items)
        storyline.append({
            "phase": "Delivery",
            "description": "Attacker delivery infrastructure and addressing anomalies.",
            "severity": severity,
            "confidence": confidence,
            "tactics": ["TA0001: Initial Access"],
            "indicators": _build_indicator_objects(delivery_items, "TA0001: Initial Access"),
        })
    else:
        storyline.append({
            "phase": "Delivery",
            "description": "Standard delivery infrastructure. No obvious addressing anomalies.",
            "severity": "low",
            "confidence": 0.9,
            "tactics": ["TA0001: Initial Access"],
            "indicators": [
                {
                    "value": "No negative delivery indicators detected.",
                    "severity": "low",
                    "confidence": 0.9,
                    "tactic": "TA0001: Initial Access",
                }
            ],
        })

    # 2. Lure Phase
    if lure_items:
        severity, confidence = _aggregate_event_stats(lure_items)
        storyline.append({
            "phase": "Lure",
            "description": "Psychological hooks and contextual targeting detected in the message.",
            "severity": severity,
            "confidence": confidence,
            "tactics": ["TA0001: Initial Access", "TA0043: Reconnaissance"],
            "indicators": _build_indicator_objects(lure_items, "TA0001: Initial Access"),
        })

    # 3. Weaponization Phase
    if weapon_items:
        severity, confidence = _aggregate_event_stats(weapon_items)
        storyline.append({
            "phase": "Weaponization",
            "description": "Suspicious payloads (URLs or Attachments) present within the lure.",
            "severity": severity,
            "confidence": confidence,
            "tactics": ["TA0001: Initial Access", "TA0002: Execution"],
            "indicators": _build_indicator_objects(weapon_items, "TA0002: Execution"),
        })

    # 4. Containment / Action Phase
    containment_severity = "high" if verdict in {"malicious", "high_risk"} else "medium" if verdict == "suspicious" else "low"
    storyline.append({
        "phase": "Containment",
        "description": f"Overall system verdict determined as '{verdict}'.",
        "severity": containment_severity,
        "confidence": 0.95,
        "tactics": ["TA0005: Defense Evasion"],
        "indicators": [
            {
                "value": f"Recommended platform actions: {', '.join(recommended_actions)}",
                "severity": containment_severity,
                "confidence": 0.95,
                "tactic": "TA0005: Defense Evasion",
            }
        ],
    })

    return storyline
