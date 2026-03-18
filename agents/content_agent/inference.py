"""Inference engine for content phishing detection models."""

from __future__ import annotations

from typing import Any

from services.logging_service import get_agent_logger

logger = get_agent_logger("content_agent")


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, round(value, 4)))


def _from_proba(value: Any) -> float:
    if isinstance(value, (list, tuple)) and value:
        return float(value[-1])
    return float(value)


def predict(features: dict[str, Any], model: Any = None) -> dict[str, Any]:
    """Run model inference and return normalized risk/confidence values."""
    logger.debug("Running inference", agent="content_agent")
    if not model:
        return {"risk_score": 0.0, "confidence": 0.0, "indicators": ["ml_model_unavailable"]}

    try:
        kind = model.get("kind") if isinstance(model, dict) else "sklearn_model"

        if kind == "transformer_pipeline":
            text = features.get("text", "")
            output = model["model"](text[:4000], truncation=True)
            row = output[0] if output else {}
            label = str(row.get("label", "")).lower()
            score = float(row.get("score", 0.0))
            risk = score if any(token in label for token in ["phish", "spam", "fraud", "malicious", "1"]) else 1.0 - score
            return {
                "risk_score": _clamp(risk),
                "confidence": _clamp(score),
                "indicators": [f"ml_transformer_label:{label}"] if label else ["ml_transformer_used"],
            }

        base_model = model.get("model") if isinstance(model, dict) else model
        vectorizer = model.get("vectorizer") if isinstance(model, dict) else None
        text = features.get("text", "")
        numeric_vector = features.get("numeric_vector")

        if vectorizer is not None:
            x = vectorizer.transform([text])
        else:
            x = numeric_vector

        if hasattr(base_model, "predict_proba"):
            proba = base_model.predict_proba(x)[0]
            risk = _from_proba(proba)
            confidence = max(float(proba.max()), 0.5)
        elif hasattr(base_model, "predict"):
            pred = base_model.predict(x)[0]
            risk = float(pred)
            confidence = 0.65
        else:
            return {"risk_score": 0.0, "confidence": 0.0, "indicators": ["ml_model_no_predict_interface"]}

        return {
            "risk_score": _clamp(risk),
            "confidence": _clamp(confidence),
            "indicators": ["ml_content_model_used"],
        }
    except Exception as exc:
        logger.warning("Content model inference failed", error=str(exc))
        return {"risk_score": 0.0, "confidence": 0.0, "indicators": ["ml_inference_failed"]}
