"""URL reputation and heuristic agent with offline fallback mode."""

from __future__ import annotations

import math
from typing import Any
from urllib.parse import urlparse

import httpx

from configs.settings import settings
from services.logging_service import get_agent_logger

logger = get_agent_logger("url_agent")


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, round(value, 4)))


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    probs = [text.count(char) / len(text) for char in set(text)]
    return -sum(prob * math.log(prob, 2) for prob in probs)


def _heuristic_score(url: str) -> tuple[float, list[str]]:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    indicators: list[str] = []
    score = 0.0

    if len(url) > 90:
        score += 0.18
        indicators.append("url_length_high")
    if host.count(".") >= 3:
        score += 0.15
        indicators.append("many_subdomains")
    if any(token in url for token in ["@", "%40", "login", "verify", "secure"]):
        score += 0.2
        indicators.append("credential_bait_terms")
    if _entropy(host) > 3.5:
        score += 0.2
        indicators.append("high_subdomain_entropy")
    if parsed.scheme != "https":
        score += 0.08
        indicators.append("non_https_url")
    return _clamp(score), indicators


def _virustotal_score(url: str) -> tuple[float, list[str]]:
    if not settings.virustotal_api_key:
        return 0.0, ["virustotal_not_configured"]

    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": settings.virustotal_api_key}

    try:
        with httpx.Client(timeout=8.0) as client:
            submit = client.post(api_url, headers=headers, data={"url": url})
            submit.raise_for_status()
            analysis_id = submit.json().get("data", {}).get("id")
            if not analysis_id:
                return 0.0, ["virustotal_no_analysis_id"]

            report = client.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
            report.raise_for_status()
            stats = report.json().get("data", {}).get("attributes", {}).get("stats", {})
            malicious = float(stats.get("malicious", 0))
            suspicious = float(stats.get("suspicious", 0))
            total = max(1.0, sum(float(v) for v in stats.values()))
            score = min(1.0, (malicious + (0.5 * suspicious)) / total)
            return round(score, 4), [f"virustotal_malicious={int(malicious)}", f"virustotal_suspicious={int(suspicious)}"]
    except Exception:
        return 0.0, ["virustotal_unavailable"]


def analyze(data: dict[str, Any]) -> dict[str, Any]:
    logger.info("Starting analysis", agent="url_agent")
    urls = data.get("urls", []) or []
    if not urls:
        return {
            "agent_name": "url_agent",
            "risk_score": 0.0,
            "confidence": 0.7,
            "indicators": ["no_urls_detected"],
        }

    scores: list[float] = []
    indicators: list[str] = []
    for url in urls[:20]:
        heur_score, heur_ind = _heuristic_score(url)
        vt_score, vt_ind = _virustotal_score(url)
        final_score = max(heur_score, (0.6 * heur_score) + (0.4 * vt_score))
        scores.append(final_score)
        indicators.extend([f"{url}::{entry}" for entry in heur_ind + vt_ind])

    risk_score = _clamp(sum(scores) / len(scores))
    result = {
        "agent_name": "url_agent",
        "risk_score": risk_score,
        "confidence": _clamp(0.6 + min(0.3, 0.02 * len(urls))),
        "indicators": indicators[:20],
    }
    logger.info("Analysis complete", risk_score=result["risk_score"], url_count=len(urls))
    return result
