"""Shared ML runtime helpers for agent model loading and inference."""

from __future__ import annotations

import pickle
from pathlib import Path
from typing import Any

import joblib


def clamp(value: float) -> float:
    return max(0.0, min(1.0, round(float(value), 4)))


def load_model_bundle(model_path: str | Path) -> Any:
    """Load a model artifact from a model directory.

    Supported artifacts:
    - model.joblib / model.pkl containing a model or dict bundle
    - local transformer folder (config.json) for text classification
    """
    path = Path(model_path)
    if not path.exists():
        return None

    for name in ("model.joblib", "model.pkl"):
        artifact = path / name
        if not artifact.exists():
            continue

        if artifact.suffix == ".joblib":
            loaded = joblib.load(artifact)
        else:
            with open(artifact, "rb") as handle:
                loaded = pickle.load(handle)

        if isinstance(loaded, dict) and "model" in loaded:
            loaded.setdefault("kind", "sklearn_bundle")
            return loaded
        return {"kind": "sklearn_model", "model": loaded}

    config_file = path / "config.json"
    if config_file.exists():
        try:
            from transformers import pipeline
        except Exception:
            return None
        pipe = pipeline(
            "text-classification",
            model=str(path),
            tokenizer=str(path),
            truncation=True,
        )
        return {"kind": "transformer_pipeline", "model": pipe}

    return None


def predict_with_model(features: dict[str, Any], model_bundle: Any, model_indicator: str) -> dict[str, Any]:
    """Run generic inference against loaded model bundle."""
    if not model_bundle:
        return {"risk_score": 0.0, "confidence": 0.0, "indicators": ["ml_model_unavailable"]}

    try:
        kind = model_bundle.get("kind") if isinstance(model_bundle, dict) else "sklearn_model"

        if kind == "transformer_pipeline":
            text = str(features.get("text", "") or "")
            output = model_bundle["model"](text[:4000], truncation=True)
            row = output[0] if output else {}
            label = str(row.get("label", "")).lower()
            score = float(row.get("score", 0.0))
            risk = score if any(token in label for token in ["phish", "spam", "fraud", "malicious", "1"]) else 1.0 - score
            return {
                "risk_score": clamp(risk),
                "confidence": clamp(score),
                "indicators": [f"ml_transformer_label:{label}"] if label else [model_indicator],
            }

        model = model_bundle.get("model") if isinstance(model_bundle, dict) else model_bundle
        vectorizer = model_bundle.get("vectorizer") if isinstance(model_bundle, dict) else None
        text = str(features.get("text", "") or "")
        numeric_vector = features.get("numeric_vector")

        if vectorizer is not None:
            x = vectorizer.transform([text])
        else:
            x = numeric_vector

        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(x)[0]
            if hasattr(proba, "tolist"):
                proba = proba.tolist()
            if isinstance(proba, list):
                risk = float(proba[-1])
                confidence = max(float(max(proba)), 0.5)
            else:
                risk = float(proba)
                confidence = max(float(proba), 0.5)
        elif hasattr(model, "predict"):
            pred = model.predict(x)[0]
            risk = float(pred)
            confidence = 0.65
        else:
            return {"risk_score": 0.0, "confidence": 0.0, "indicators": ["ml_model_no_predict_interface"]}

        return {
            "risk_score": clamp(risk),
            "confidence": clamp(confidence),
            "indicators": [model_indicator],
        }
    except Exception:
        return {"risk_score": 0.0, "confidence": 0.0, "indicators": ["ml_inference_failed"]}
