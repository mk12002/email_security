"""Feature extraction for user interaction prediction models."""

from __future__ import annotations

from typing import Any

import numpy as np

from services.logging_service import get_agent_logger

logger = get_agent_logger("user_behavior_agent")

URGENCY_TERMS = {"urgent", "immediately", "verify", "final notice", "action required"}
FAMILIAR_DOMAINS = {"company.com", "microsoft.com", "google.com", "github.com"}


def extract_features(data: dict[str, Any]) -> dict[str, Any]:
    """Build click-risk features from sender familiarity and urgency cues."""
    logger.debug("Extracting features", agent="user_behavior_agent")

    headers = data.get("headers", {}) or {}
    subject = str(headers.get("subject", "") or "").lower()
    sender = str(headers.get("sender", "") or "").lower()
    urls = data.get("urls", []) or []

    sender_domain = sender.split("@")[-1] if "@" in sender else sender
    familiarity = 1.0 if sender_domain in FAMILIAR_DOMAINS else 0.0
    urgency_hits = float(sum(1 for term in URGENCY_TERMS if term in subject))
    link_count = float(len(urls))
    subject_len = float(len(subject))

    numeric_vector = np.array(
        [
            familiarity,
            urgency_hits,
            link_count,
            subject_len,
        ],
        dtype=float,
    ).reshape(1, -1)

    return {
        "text": subject,
        "numeric_vector": numeric_vector,
        "metrics": {
            "sender_familiarity": familiarity,
            "urgency_hits": urgency_hits,
            "link_count": link_count,
        },
    }
