"""Inference engine for sandbox behavior models."""

from __future__ import annotations

from typing import Any

from agents.ml_runtime import predict_with_model
from preprocessing.sandbox_feature_contract import build_numeric_feature_map
from services.logging_service import get_agent_logger

logger = get_agent_logger("sandbox_agent")


def predict(features: dict[str, Any], model: Any = None) -> dict[str, Any]:
    """Run inference using sandbox model bundle and normalized feature map."""
    logger.debug("Running inference", agent="sandbox_agent")
    feature_map = build_numeric_feature_map(features)
    prediction = predict_with_model(
        {
            "feature_map": feature_map,
            "numeric_vector": [[feature_map[k] for k in feature_map]],
        },
        model_bundle=model,
        model_indicator="ml_sandbox_model_used",
    )

    threshold = None
    if isinstance(model, dict):
        threshold = model.get("threshold")
    if isinstance(threshold, (int, float)):
        prediction["decision_threshold"] = float(threshold)
        prediction["predicted_label"] = int(prediction.get("risk_score", 0.0) >= float(threshold))

    logger.debug("Inference complete", prediction=prediction)
    return prediction
