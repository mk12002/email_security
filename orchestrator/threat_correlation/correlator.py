"""
Threat Correlation Engine for the Agentic Email Security System.

Correlates findings across agents to identify coordinated attack patterns.
"""

from typing import Any

from services.logging_service import get_service_logger

logger = get_service_logger("threat_correlation")


def correlate_threats(agent_results: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Correlate threat indicators across multiple agent results.

    Args:
        agent_results: List of standardized agent result dictionaries.

    Returns:
        Correlation report with identified patterns and cross-agent relationships.
    """
    logger.info("Correlating threats", agent_count=len(agent_results))

    normalized: dict[str, set[str]] = {}
    for result in agent_results:
        name = result.get("agent_name", "unknown")
        indicators = {
            str(item).split("::")[-1].split(":")[-1].strip().lower()
            for item in result.get("indicators", [])
            if str(item).strip()
        }
        normalized[name] = indicators

    overlap_counts: dict[str, int] = {}
    for indicator_set in normalized.values():
        for indicator in indicator_set:
            overlap_counts[indicator] = overlap_counts.get(indicator, 0) + 1

    correlated = [key for key, count in overlap_counts.items() if count >= 2]
    patterns: list[str] = []
    if any("lookalike" in item or "spoof" in item for item in correlated):
        patterns.append("domain_spoofing_campaign")
    if any("urgency" in item or "credential" in item for item in correlated):
        patterns.append("credential_harvest_pattern")
    if any("macro" in item or "virtualalloc" in item or "risky_executable" in item for item in correlated):
        patterns.append("malware_delivery_pattern")

    correlation = {
        "correlated_indicators": sorted(correlated),
        "attack_patterns": patterns,
        "correlation_score": round(min(1.0, len(correlated) / 8), 4),
    }

    logger.info("Correlation complete", patterns_found=len(correlation["attack_patterns"]))
    return correlation
