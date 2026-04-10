"""URL reputation and heuristic agent with offline fallback mode."""

from __future__ import annotations

import math
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from email_security.agents.url_agent.feature_extractor import extract_features
from email_security.agents.url_agent.inference import predict
from email_security.agents.url_agent.model_loader import load_model
from email_security.configs.settings import settings
from email_security.services.logging_service import get_agent_logger

logger = get_agent_logger("url_agent")

_OPENPHISH_CACHE: dict[str, Any] = {"fetched_at": 0.0, "urls": set()}


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

    if len(url) > 75:
        score += 0.18
        indicators.append("url_length_high")
    if host.count(".") >= 2:
        score += 0.25
        indicators.append("many_subdomains")
    if any(token in url for token in ["@", "%40", "login", "verify", "secure", "reset", "auth", "signin", "account"]):
        score += 0.4
        indicators.append("credential_bait_terms")
    if _entropy(host) > 3.5:
        score += 0.25
        indicators.append("high_subdomain_entropy")
    if parsed.scheme != "https":
        score += 0.15
        indicators.append("non_https_url")
    return _clamp(score), indicators


def _request_timeout() -> float:
    return max(1.0, float(settings.external_lookup_timeout_seconds))


def _virustotal_score(url: str) -> tuple[float, list[str]]:
    if not settings.enable_virustotal_url_lookup:
        return 0.0, []
    if not settings.virustotal_api_key:
        return 0.0, ["virustotal_not_configured"]

    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": settings.virustotal_api_key}

    try:
        with httpx.Client(timeout=_request_timeout()) as client:
            submit = client.post(api_url, headers=headers, data={"url": url})
            submit.raise_for_status()
            analysis_id = submit.json().get("data", {}).get("id")
            if not analysis_id:
                return 0.0, []

            report = client.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
            report.raise_for_status()
            stats = report.json().get("data", {}).get("attributes", {}).get("stats", {})
            malicious = float(stats.get("malicious", 0))
            suspicious = float(stats.get("suspicious", 0))
            total = max(1.0, sum(float(v) for v in stats.values()))
            score = min(1.0, (malicious + (0.5 * suspicious)) / total)
            if score <= 0.0:
                return 0.0, []
            return round(score, 4), [f"virustotal_malicious={int(malicious)}", f"virustotal_suspicious={int(suspicious)}"]
    except Exception:
        return 0.0, ["virustotal_unavailable"]


def _google_safe_browsing_score(url: str) -> tuple[float, list[str]]:
    if not settings.enable_google_safe_browsing_lookup:
        return 0.0, []
    if not settings.google_safe_browsing_api_key:
        return 0.0, ["google_safe_browsing_not_configured"]

    api_url = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={settings.google_safe_browsing_api_key}"
    )
    payload = {
        "client": {
            "clientId": "email_security_platform",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        with httpx.Client(timeout=_request_timeout()) as client:
            response = client.post(api_url, json=payload)
            response.raise_for_status()
            matches = response.json().get("matches", []) or []
            if not matches:
                return 0.0, []
            threat_types = sorted(
                {
                    str(match.get("threatType", "unknown")).lower()
                    for match in matches
                    if isinstance(match, dict)
                }
            )
            score = min(1.0, 0.75 + (0.05 * len(matches)))
            indicators = [f"google_safe_browsing_match={item}" for item in threat_types[:3]]
            return _clamp(score), indicators
    except Exception:
        return 0.0, ["google_safe_browsing_unavailable"]


def _openphish_score(url: str) -> tuple[float, list[str]]:
    if not settings.enable_openphish_lookup:
        return 0.0, []

    feed_url = (settings.openphish_feed_url or "").strip()
    if not feed_url:
        return 0.0, ["openphish_not_configured"]

    try:
        ttl = max(60, int(settings.openphish_cache_ttl_seconds))
        now = time.time()
        cache_age = now - float(_OPENPHISH_CACHE.get("fetched_at", 0.0))
        cached_urls = _OPENPHISH_CACHE.get("urls")

        if not isinstance(cached_urls, set) or not cached_urls or cache_age > ttl:
            with httpx.Client(timeout=_request_timeout()) as client:
                response = client.get(feed_url)
                response.raise_for_status()
                lines = response.text.splitlines()

            cached_urls = {
                line.strip().rstrip("/")
                for line in lines
                if line.strip() and not line.strip().startswith("#")
            }
            _OPENPHISH_CACHE["urls"] = cached_urls
            _OPENPHISH_CACHE["fetched_at"] = now

        needle = str(url).strip().rstrip("/")
        if needle and needle in cached_urls:
            return 0.95, ["openphish_match"]
        return 0.0, []
    except Exception:
        return 0.0, ["openphish_unavailable"]


def _urlhaus_score(url: str) -> tuple[float, list[str]]:
    if not settings.enable_urlhaus_lookup:
        return 0.0, []

    api_url = (settings.urlhaus_api_url or "").strip()
    if not api_url:
        return 0.0, ["urlhaus_not_configured"]

    try:
        with httpx.Client(timeout=_request_timeout()) as client:
            response = client.post(api_url, data={"url": url})
            response.raise_for_status()
            payload = response.json()

        status = str(payload.get("query_status", "")).lower()
        if status != "ok":
            return 0.0, []

        url_status = str(payload.get("url_status", "unknown")).lower()
        tags = payload.get("tags") or []
        threat = str(payload.get("threat", "")).lower()
        score = 0.92 if url_status == "online" else 0.82
        indicators = [f"urlhaus_status={url_status}"]
        if threat:
            indicators.append(f"urlhaus_threat={threat}")
        if isinstance(tags, list) and tags:
            indicators.append(f"urlhaus_tag={str(tags[0]).lower()}")
        return _clamp(score), indicators
    except Exception:
        return 0.0, ["urlhaus_unavailable"]


def _external_score(url: str) -> tuple[float, list[str]]:
    provider_scores: list[float] = []
    indicators: list[str] = []
    for lookup in (
        _google_safe_browsing_score,
        _openphish_score,
        _urlhaus_score,
        _virustotal_score,
    ):
        score, provider_indicators = lookup(url)
        if score > 0.0:
            provider_scores.append(score)
        indicators.extend(provider_indicators)

    if not provider_scores:
        return 0.0, indicators
    return _clamp(max(provider_scores)), indicators


def _any_external_lookup_enabled() -> bool:
    return any(
        (
            settings.enable_google_safe_browsing_lookup,
            settings.enable_openphish_lookup,
            settings.enable_urlhaus_lookup,
            settings.enable_virustotal_url_lookup,
        )
    )


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

    combined_scores: list[float] = []
    heuristic_scores: list[float] = []
    external_scores: list[float] = []
    url_level_indicators: list[str] = []
    for url in urls[:20]:
        heur_score, heur_ind = _heuristic_score(url)
        external_score, external_ind = _external_score(url)
        final_score = max(heur_score, _clamp((0.45 * heur_score) + (0.55 * external_score)))
        combined_scores.append(final_score)
        heuristic_scores.append(heur_score)
        external_scores.append(external_score)
        url_level_indicators.extend([f"{url}::{entry}" for entry in heur_ind + external_ind])

    heuristic_risk = _clamp(sum(heuristic_scores) / len(heuristic_scores))
    external_risk = _clamp(sum(external_scores) / len(external_scores))
    evidence_risk = _clamp(
        max(
            sum(combined_scores) / len(combined_scores),
            (0.65 * heuristic_risk) + (0.35 * external_risk),
        )
    )

    summary_indicators = [
        f"urls_analyzed={len(combined_scores)}",
        f"heuristic_risk={heuristic_risk}",
        f"external_risk={external_risk}",
    ]
    if _any_external_lookup_enabled():
        summary_indicators.append("external_lookups_enabled")
    else:
        summary_indicators.append("external_lookups_disabled")

    features = extract_features(data)
    model = load_model()
    ml_prediction = predict(features, model=model)

    if ml_prediction.get("confidence", 0.0) > 0.0:
        ml_risk = ml_prediction.get("risk_score", 0.0)
        risk_score = _clamp(max(ml_risk, evidence_risk, (0.6 * ml_risk) + (0.4 * evidence_risk)))
        confidence_floor = 0.6 + min(0.25, 0.02 * len(urls)) + (0.05 if external_risk > 0.0 else 0.0)
        confidence = _clamp(max(confidence_floor, ml_prediction.get("confidence", 0.0)))
        summary_indicators.extend(ml_prediction.get("indicators", []))
    else:
        risk_score = evidence_risk
        confidence = _clamp(0.6 + min(0.25, 0.02 * len(urls)) + (0.08 if external_risk > 0.0 else 0.0))

    result = {
        "agent_name": "url_agent",
        "risk_score": risk_score,
        "confidence": confidence,
        "indicators": (summary_indicators + url_level_indicators)[:20],
    }
    logger.info("Analysis complete", risk_score=result["risk_score"], url_count=len(urls))
    return result
