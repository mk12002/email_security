"""Feature extraction for URL reputation models."""

from __future__ import annotations

import math
from typing import Any
from urllib.parse import urlparse

import numpy as np

from services.logging_service import get_agent_logger

logger = get_agent_logger("url_agent")


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    probs = [text.count(char) / len(text) for char in set(text)]
    return -sum(prob * math.log(prob, 2) for prob in probs)


def extract_features(data: dict[str, Any]) -> dict[str, Any]:
    """Build aggregated URL lexical features for XGBoost/sklearn-style models."""
    logger.debug("Extracting features", agent="url_agent")

    urls = [str(item) for item in (data.get("urls", []) or []) if str(item).strip()][:20]
    if not urls:
        numeric_vector = np.zeros((1, 6), dtype=float)
        return {"text": "", "numeric_vector": numeric_vector, "metrics": {"url_count": 0}}

    lengths: list[float] = []
    subdomains: list[float] = []
    special_chars: list[float] = []
    entropies: list[float] = []
    insecure_ratio = 0.0
    bait_ratio = 0.0

    for url in urls:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        lengths.append(float(len(url)))
        subdomains.append(float(max(0, host.count(".") - 1)))
        special_chars.append(float(sum(1 for c in url if not c.isalnum())))
        entropies.append(float(_entropy(host)))
        insecure_ratio += 1.0 if parsed.scheme != "https" else 0.0
        bait_ratio += 1.0 if any(token in url.lower() for token in ["login", "verify", "secure", "update"]) else 0.0

    count = float(len(urls))
    numeric_vector = np.array(
        [
            sum(lengths) / count,
            sum(subdomains) / count,
            sum(special_chars) / count,
            sum(entropies) / count,
            insecure_ratio / count,
            bait_ratio / count,
        ],
        dtype=float,
    ).reshape(1, -1)

    return {
        "text": "\n".join(urls),
        "numeric_vector": numeric_vector,
        "metrics": {
            "url_count": len(urls),
            "avg_length": numeric_vector[0][0],
            "avg_entropy": numeric_vector[0][3],
        },
    }
