"""Inference engine for user interaction prediction models."""

from __future__ import annotations

from typing import Any

from agents.ml_runtime import predict_with_model
from services.logging_service import get_agent_logger

logger = get_agent_logger("user_behavior_agent")


def predict(features: dict[str, Any], model: Any = None) -> dict[str, Any]:
    """Run inference for user-behavior model and return normalized risk output."""
    logger.debug("Running inference", agent="user_behavior_agent")
    prediction = predict_with_model(features, model, model_indicator="ml_user_behavior_model_used")
    logger.debug("Inference complete", prediction=prediction)
    return prediction
