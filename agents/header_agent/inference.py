"""
Inference engine for the Header Analysis Agent.

Runs the loaded model against extracted features to produce predictions.
"""

from typing import Any

from services.logging_service import get_agent_logger

logger = get_agent_logger("header_agent")


def predict(features: dict[str, Any], model: Any = None) -> dict[str, Any]:
    """
    Run inference using the agent model.

    Args:
        features: Extracted feature dictionary.
        model: Pre-loaded model object (optional).

    Returns:
        Prediction result with risk_score and confidence.
    """
    logger.debug("Running inference", agent="header_agent")

    prediction = {
        "risk_score": 0.0,
        "confidence": 0.0,
        "indicators": [],
    }

    if not model or "numeric_vector" not in features:
        return prediction

    try:
        vec = features["numeric_vector"]
        probs = model.predict_proba(vec)[0]
        risk = float(probs[1])
        conf = float(abs(probs[1] - probs[0]))
        
        prediction["risk_score"] = risk
        prediction["confidence"] = conf
        if risk > 0.5:
            prediction["indicators"].append("ml_header_anomaly")
            
    except Exception as e:
        logger.error("Inference failed", error=str(e))

    logger.debug("Inference complete", prediction=prediction)
    return prediction
