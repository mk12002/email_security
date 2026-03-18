"""Attachment static analysis agent using lightweight EMBER-like feature checks."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

from agents.attachment_agent.feature_extractor import extract_features
from agents.attachment_agent.inference import predict
from agents.attachment_agent.model_loader import load_model
from services.logging_service import get_agent_logger

logger = get_agent_logger("attachment_agent")

SUSPICIOUS_IMPORT_STRINGS = [b"VirtualAlloc", b"WriteProcessMemory", b"CreateRemoteThread", b"powershell"]
SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".scr", ".js", ".vbs", ".hta", ".ps1", ".docm", ".xlsm"}


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, round(value, 4)))


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    probs = [count / len(data) for count in freq if count]
    return -sum(prob * math.log(prob, 2) for prob in probs)


def analyze(data: dict[str, Any]) -> dict[str, Any]:
    logger.info("Starting analysis", agent="attachment_agent")
    attachments = data.get("attachments", []) or []
    if not attachments:
        return {
            "agent_name": "attachment_agent",
            "risk_score": 0.0,
            "confidence": 0.8,
            "indicators": ["no_attachments"],
        }

    cumulative = 0.0
    indicators: list[str] = []

    for attachment in attachments[:10]:
        path = Path(attachment.get("path", ""))
        file_score = 0.0
        extension = path.suffix.lower()

        if extension in SUSPICIOUS_EXTENSIONS:
            file_score += 0.28
            indicators.append(f"suspicious_extension:{path.name}")

        if path.exists() and path.is_file():
            blob = path.read_bytes()
            entropy = _entropy(blob)
            if entropy >= 7.1:
                file_score += 0.22
                indicators.append(f"high_entropy:{path.name}")

            if any(token in blob for token in SUSPICIOUS_IMPORT_STRINGS):
                file_score += 0.32
                indicators.append(f"suspicious_imports:{path.name}")

            if extension in {".docm", ".xlsm"} and b"vba" in blob.lower():
                file_score += 0.25
                indicators.append(f"office_macro_presence:{path.name}")
        else:
            indicators.append(f"missing_attachment_path:{attachment.get('filename', 'unknown')}")

        cumulative += _clamp(file_score)

    avg_score = cumulative / max(1, len(attachments[:10]))
    heuristic_result = {
        "agent_name": "attachment_agent",
        "risk_score": _clamp(avg_score),
        "confidence": _clamp(0.6 + min(0.3, len(attachments) * 0.03)),
        "indicators": indicators[:20],
    }

    features = extract_features(data)
    model = load_model()
    ml_prediction = predict(features, model=model)

    if ml_prediction.get("confidence", 0.0) > 0.0:
        risk_score = _clamp((0.65 * ml_prediction.get("risk_score", 0.0)) + (0.35 * heuristic_result["risk_score"]))
        confidence = _clamp(max(heuristic_result["confidence"], ml_prediction.get("confidence", 0.0)))
        merged_indicators = (heuristic_result["indicators"] + ml_prediction.get("indicators", []))[:20]
    else:
        risk_score = heuristic_result["risk_score"]
        confidence = heuristic_result["confidence"]
        merged_indicators = heuristic_result["indicators"]

    result = {
        "agent_name": "attachment_agent",
        "risk_score": risk_score,
        "confidence": confidence,
        "indicators": merged_indicators,
    }

    logger.info("Analysis complete", risk_score=result["risk_score"])
    return result
