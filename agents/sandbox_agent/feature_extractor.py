"""
Feature extractor for the Sandbox Behavior Agent.

Transforms raw email data into feature vectors for model inference.
"""

from typing import Any

from services.logging_service import get_agent_logger

logger = get_agent_logger("sandbox_agent")


def extract_features(data: dict[str, Any]) -> dict[str, Any]:
    """
    Extract features from raw email data.

    Args:
        data: Raw email data relevant to this agent.

    Returns:
        Dictionary of extracted features ready for model inference.
    """
    logger.debug("Extracting features", agent="sandbox_agent")

    # Placeholder – feature engineering logic will be added in later phases
    features = {}

    logger.debug("Features extracted", feature_count=len(features))
    return features
