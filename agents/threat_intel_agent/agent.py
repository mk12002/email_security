"""Threat intelligence agent backed by local IOC feed lookup."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd

from services.logging_service import get_agent_logger

logger = get_agent_logger("threat_intel_agent")


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, round(value, 4)))


def _load_ioc_set() -> set[str]:
    root = Path("datasets/threat_intelligence")
    values: set[str] = set()
    if not root.exists():
        return values

    for csv_file in root.rglob("*.csv"):
        try:
            frame = pd.read_csv(csv_file)
            for column in frame.columns:
                values.update(str(item).strip().lower() for item in frame[column].dropna().tolist())
        except Exception:
            continue

    for json_file in root.rglob("*.json"):
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
            if isinstance(data, list):
                for item in data:
                    values.add(str(item).strip().lower())
            elif isinstance(data, dict):
                for item in data.values():
                    if isinstance(item, list):
                        values.update(str(entry).strip().lower() for entry in item)
                    else:
                        values.add(str(item).strip().lower())
        except Exception:
            continue
    return values


def analyze(data: dict[str, Any]) -> dict[str, Any]:
    logger.info("Starting analysis", agent="threat_intel_agent")
    ioc_lookup = _load_ioc_set()
    iocs = data.get("iocs", {}) or {}
    candidates = []
    candidates.extend(iocs.get("domains", []) or [])
    candidates.extend(iocs.get("ips", []) or [])
    candidates.extend(iocs.get("hashes", []) or [])

    matches = [value for value in candidates if str(value).lower() in ioc_lookup]
    risk = min(1.0, 0.25 * len(matches))

    result = {
        "agent_name": "threat_intel_agent",
        "risk_score": _clamp(risk),
        "confidence": _clamp(0.4 if not ioc_lookup else 0.8),
        "indicators": [f"ioc_match:{entry}" for entry in matches[:20]] or ["no_local_ioc_hits"],
    }
    logger.info("Analysis complete", risk_score=result["risk_score"], matches=len(matches))
    return result
