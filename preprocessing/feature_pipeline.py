"""
Feature engineering pipeline for local model training (RTX 4050 workflow).
"""

from __future__ import annotations

import math
import re
from pathlib import Path

import pandas as pd

URL_REGEX = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    probs = [value.count(char) / len(value) for char in set(value)]
    return float(-sum(prob * math.log(prob, 2) for prob in probs))


def build_url_features(urls: list[str], label: int) -> pd.DataFrame:
    rows = []
    for url in urls:
        host = re.sub(r"^https?://", "", url).split("/")[0]
        rows.append(
            {
                "url": url,
                "url_length": len(url),
                "subdomain_count": max(0, host.count(".") - 1),
                "special_char_count": sum(1 for char in url if not char.isalnum()),
                "host_entropy": _entropy(host),
                "label": label,
            }
        )
    return pd.DataFrame(rows)


def build_content_features(email_rows: list[dict]) -> pd.DataFrame:
    rows = []
    for item in email_rows:
        content = (item.get("content") or "").lower()
        rows.append(
            {
                "text": item.get("content") or "",
                "word_count": len(content.split()),
                "urgency_count": sum(1 for term in ["urgent", "verify", "immediately"] if term in content),
                "url_count": len(URL_REGEX.findall(content)),
                "label": int(item.get("label", 0)),
            }
        )
    return pd.DataFrame(rows)


def write_processed_dataset(frame: pd.DataFrame, output_file: str | Path) -> str:
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(output_path, index=False)
    return str(output_path)
