"""Threat intelligence agent backed by local IOC feed lookup."""

from __future__ import annotations

import csv
import json
import sqlite3
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from email_security.configs import settings
from email_security.services.logging_service import get_agent_logger

# Import the ML Pipeline components
from email_security.agents.threat_intel_agent.feature_extractor import extract_features
from email_security.agents.threat_intel_agent.model_loader import load_model
from email_security.agents.threat_intel_agent.inference import predict

logger = get_agent_logger("threat_intel_agent")

IOC_SOURCE_ROOT = Path("datasets/threat_intelligence")
URL_FALLBACK_ROOT = Path("datasets/url_dataset/malicious")


class IOCStore:
    """Persistent local IOC database backed by SQLite for fast membership checks."""

    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        if not self.db_path.is_absolute():
            self.db_path = Path(".") / self.db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self.db_path))

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS iocs (
                    indicator TEXT PRIMARY KEY,
                    ioc_type TEXT,
                    source TEXT,
                    first_seen_ts INTEGER,
                    updated_ts INTEGER
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            conn.commit()

    def get_last_refresh_ts(self) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM metadata WHERE key = 'last_refresh_ts'"
            ).fetchone()
            return int(row[0]) if row else 0

    def _set_last_refresh_ts(self, ts: int) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO metadata(key, value)
                VALUES('last_refresh_ts', ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value
                """,
                (str(ts),),
            )
            conn.commit()

    def upsert_many(self, rows: list[tuple[str, str, str]]) -> int:
        if not rows:
            return 0
        now = int(time.time())
        normalized = []
        for indicator, ioc_type, source in rows:
            value = str(indicator).strip().lower()
            if not value:
                continue
            normalized.append((value, ioc_type, source, now, now))

        if not normalized:
            return 0

        with self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO iocs(indicator, ioc_type, source, first_seen_ts, updated_ts)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(indicator)
                DO UPDATE SET
                  ioc_type = excluded.ioc_type,
                  source = excluded.source,
                  updated_ts = excluded.updated_ts
                """,
                normalized,
            )
            conn.commit()
        return len(normalized)

    def lookup(self, candidates: list[str]) -> list[str]:
        values = [str(item).strip().lower() for item in candidates if str(item).strip()]
        if not values:
            return []

        placeholders = ",".join("?" for _ in values)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT indicator FROM iocs WHERE indicator IN ({placeholders})",
                values,
            ).fetchall()
        return [row[0] for row in rows]

    def count(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()
            return int(row[0]) if row else 0


def _extract_domain(value: str) -> str:
    parsed = urlparse(value)
    if parsed.hostname:
        return parsed.hostname.lower()
    return ""


def _ioc_type_for(value: str) -> str:
    if not value:
        return "unknown"
    lowered = value.lower()
    if lowered.startswith("http://") or lowered.startswith("https://"):
        return "url"
    if lowered.count(".") == 3 and all(part.isdigit() for part in lowered.split(".")):
        return "ip"
    if "." in lowered and " " not in lowered:
        return "domain"
    if len(lowered) in {32, 40, 64} and all(char in "0123456789abcdef" for char in lowered):
        return "hash"
    return "unknown"


def _read_csv_iocs(file_path: Path) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    try:
        with file_path.open("r", encoding="utf-8", errors="ignore") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                if not row:
                    continue
                for value in row.values():
                    item = str(value).strip()
                    if not item:
                        continue
                    rows.append((item, _ioc_type_for(item), file_path.name))
                    if _ioc_type_for(item) == "url":
                        domain = _extract_domain(item)
                        if domain:
                            rows.append((domain, "domain", f"{file_path.name}:derived"))
    except Exception:
        return []
    return rows


def _read_json_iocs(file_path: Path) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    try:
        data = json.loads(file_path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return []

    def push(value: Any) -> None:
        item = str(value).strip()
        if not item:
            return
        rows.append((item, _ioc_type_for(item), file_path.name))
        if _ioc_type_for(item) == "url":
            domain = _extract_domain(item)
            if domain:
                rows.append((domain, "domain", f"{file_path.name}:derived"))

    if isinstance(data, list):
        for entry in data:
            if isinstance(entry, dict):
                for value in entry.values():
                    if isinstance(value, list):
                        for nested in value:
                            push(nested)
                    else:
                        push(value)
            else:
                push(entry)
    elif isinstance(data, dict):
        for value in data.values():
            if isinstance(value, list):
                for nested in value:
                    push(nested)
            else:
                push(value)

    return rows


def _read_txt_iocs(file_path: Path) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    try:
        for line in file_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            item = line.strip()
            if not item or item.startswith("#"):
                continue
            rows.append((item, _ioc_type_for(item), file_path.name))
            if _ioc_type_for(item) == "url":
                domain = _extract_domain(item)
                if domain:
                    rows.append((domain, "domain", f"{file_path.name}:derived"))
    except Exception:
        return []
    return rows


def _collect_iocs_from_feeds() -> list[tuple[str, str, str]]:
    """Ingest IOCs from the cleaned, unified dataset rather than raw feeds."""
    rows: list[tuple[str, str, str]] = []
    
    # Locate the unified processed CSV
    unified_path = Path("datasets_processed/threat_intel/unified_ioc_reference.csv")
    if not unified_path.is_absolute():
        from email_security.configs.settings import PROJECT_ROOT
        unified_path = PROJECT_ROOT / unified_path

    if not unified_path.exists():
        logger.warning(f"Unified IOC reference not found at {unified_path}. Run preprocessing first.")
        return rows

    try:
        with unified_path.open("r", encoding="utf-8", errors="ignore") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                indicator = (row.get("indicator") or "").strip().lower()
                ioc_type = (row.get("ioc_type") or "").strip().lower()
                source = (row.get("source") or "unified_reference").strip()
                
                if not indicator or not ioc_type:
                    continue
                    
                rows.append((indicator, ioc_type, source))
                # Note: No need to derive domains from URLs here because the 
                # preprocessing built-in logic already derived and saved them explicitly.
    except Exception as e:
        logger.error(f"Failed to read unified IOC reference: {e}")
        
    return rows


_STORE = IOCStore(settings.ioc_db_path)


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, round(value, 4)))


def _evaluate_ioc_health(last_refresh_age_seconds: int | None, total_iocs: int) -> tuple[str, list[str]]:
    """Evaluate IOC store health level based on staleness and minimum data policy."""
    violations: list[str] = []
    warning_age = max(60, int(settings.ioc_warning_age_seconds))
    critical_age = max(warning_age, int(settings.ioc_critical_age_seconds))
    min_records = max(1, int(settings.ioc_min_records))

    level = "healthy"
    if last_refresh_age_seconds is None:
        violations.append("ioc_refresh_never_recorded")
        level = "critical"
    elif int(last_refresh_age_seconds) > critical_age:
        violations.append(f"ioc_age_exceeds_critical:{int(last_refresh_age_seconds)}>{critical_age}")
        level = "critical"
    elif int(last_refresh_age_seconds) > warning_age:
        violations.append(f"ioc_age_exceeds_warning:{int(last_refresh_age_seconds)}>{warning_age}")
        level = "warning"

    if int(total_iocs) < min_records:
        violations.append(f"ioc_record_count_low:{int(total_iocs)}<{min_records}")
        if level == "healthy":
            level = "warning"

    return level, violations


def _refresh_ioc_store_if_needed() -> int:
    now = int(time.time())
    last_refresh = _STORE.get_last_refresh_ts()
    if last_refresh and (now - last_refresh) < max(30, settings.ioc_refresh_seconds):
        return _STORE.count()

    harvested = _collect_iocs_from_feeds()
    upserted = _STORE.upsert_many(harvested)
    _STORE._set_last_refresh_ts(now)
    total = _STORE.count()
    logger.info(
        "IOC store refreshed",
        harvested=len(harvested),
        upserted=upserted,
        total=total,
        db_path=str(_STORE.db_path),
    )
    return total


def get_ioc_store_status() -> dict[str, Any]:
    """Return IOC store metadata and policy-driven health indicators."""
    now = int(time.time())
    total_iocs = _STORE.count()
    last_refresh_ts = int(_STORE.get_last_refresh_ts() or 0)
    last_refresh_age_seconds: int | None = None
    if last_refresh_ts > 0:
        last_refresh_age_seconds = max(0, now - last_refresh_ts)

    stale_after_seconds = max(60, int(settings.ioc_stale_seconds))
    is_stale = (
        last_refresh_age_seconds is None
        or int(last_refresh_age_seconds) > stale_after_seconds
    )

    health_level, policy_violations = _evaluate_ioc_health(
        last_refresh_age_seconds,
        total_iocs=total_iocs,
    )

    return {
        "db_path": str(_STORE.db_path),
        "total_iocs": int(total_iocs),
        "last_refresh_ts": int(last_refresh_ts),
        "last_refresh_age_seconds": last_refresh_age_seconds,
        "stale_after_seconds": int(stale_after_seconds),
        "is_stale": bool(is_stale),
        "health_level": str(health_level),
        "policy_violations": [str(item) for item in policy_violations],
    }


def refresh_ioc_store(force: bool = False) -> dict[str, Any]:
    """Refresh IOC store from feeds and return refresh summary with current status."""
    now = int(time.time())
    refreshed = False
    harvested = 0
    upserted = 0

    refresh_interval = max(30, int(settings.ioc_refresh_seconds))
    last_refresh_ts = int(_STORE.get_last_refresh_ts() or 0)
    should_refresh = bool(force) or (not last_refresh_ts) or ((now - last_refresh_ts) >= refresh_interval)

    if should_refresh:
        rows = _collect_iocs_from_feeds()
        harvested = len(rows)
        upserted = _STORE.upsert_many(rows)
        _STORE._set_last_refresh_ts(now)
        refreshed = True

    status = get_ioc_store_status()
    return {
        "force": bool(force),
        "refreshed": bool(refreshed),
        "harvested": int(harvested),
        "upserted": int(upserted),
        "total_iocs": int(status.get("total_iocs", 0)),
        "status": status,
    }


def _request_timeout() -> float:
    return max(1.0, float(settings.external_lookup_timeout_seconds))


def _limit_indicators(values: list[str]) -> list[str]:
    max_items = max(1, int(settings.external_lookup_max_indicators))
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = str(value).strip().lower()
        if not item or item in seen:
            continue
        seen.add(item)
        deduped.append(item)
        if len(deduped) >= max_items:
            break
    return deduped


def _otx_indicator_type(indicator: str) -> str:
    kind = _ioc_type_for(indicator)
    if kind == "ip":
        return "IPv4"
    if kind == "hash":
        return "file"
    return "domain"


def _otx_score(candidates: list[str]) -> tuple[float, list[str]]:
    if not settings.enable_otx_lookup:
        return 0.0, []
    if not settings.otx_api_key:
        return 0.0, ["otx_not_configured"]

    base_url = str(settings.otx_api_base_url).rstrip("/")
    headers = {"X-OTX-API-KEY": settings.otx_api_key}
    scores: list[float] = []
    indicators: list[str] = []

    for indicator in _limit_indicators(candidates):
        indicator_type = _otx_indicator_type(indicator)
        endpoint = f"{base_url}/api/v1/indicators/{indicator_type}/{quote(indicator, safe='')}/general"
        try:
            with httpx.Client(timeout=_request_timeout()) as client:
                response = client.get(endpoint, headers=headers)
                response.raise_for_status()
                payload = response.json()
            pulse_count = int((payload.get("pulse_info", {}) or {}).get("count", 0) or 0)
            if pulse_count > 0:
                scores.append(min(1.0, 0.3 + (0.1 * pulse_count)))
                indicators.append(f"otx_hit:{indicator_type.lower()}:{indicator}")
        except Exception:
            indicators.append("otx_unavailable")
            break

    if not scores:
        return 0.0, indicators
    return _clamp(max(scores)), indicators


def _abuseipdb_score(ips: list[str]) -> tuple[float, list[str]]:
    if not settings.enable_abuseipdb_lookup:
        return 0.0, []
    if not settings.abuseipdb_api_key:
        return 0.0, ["abuseipdb_not_configured"]

    api_url = str(settings.abuseipdb_api_url).strip()
    if not api_url:
        return 0.0, ["abuseipdb_not_configured"]

    headers = {"Key": settings.abuseipdb_api_key, "Accept": "application/json"}
    scores: list[float] = []
    indicators: list[str] = []

    for ip in _limit_indicators(ips):
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        try:
            with httpx.Client(timeout=_request_timeout()) as client:
                response = client.get(api_url, headers=headers, params=params)
                response.raise_for_status()
                payload = response.json().get("data", {}) or {}
            abuse_score = float(payload.get("abuseConfidenceScore", 0.0) or 0.0)
            normalized = _clamp(abuse_score / 100.0)
            if normalized > 0.0:
                scores.append(normalized)
            if abuse_score >= 25.0:
                indicators.append(f"abuseipdb_high_confidence:{ip}:{int(abuse_score)}")
        except Exception:
            indicators.append("abuseipdb_unavailable")
            break

    if not scores:
        return 0.0, indicators
    return _clamp(max(scores)), indicators


def _malwarebazaar_score(hashes: list[str]) -> tuple[float, list[str]]:
    if not settings.enable_malwarebazaar_lookup:
        return 0.0, []

    api_url = str(settings.malwarebazaar_api_url).strip()
    if not api_url:
        return 0.0, ["malwarebazaar_not_configured"]

    scores: list[float] = []
    indicators: list[str] = []

    for file_hash in _limit_indicators(hashes):
        body = {"query": "get_info", "hash": file_hash}
        try:
            with httpx.Client(timeout=_request_timeout()) as client:
                response = client.post(api_url, data=body)
                response.raise_for_status()
                payload = response.json()

            status = str(payload.get("query_status", "")).lower()
            if status == "ok" and payload.get("data"):
                scores.append(0.95)
                indicators.append(f"malwarebazaar_hit:{file_hash[:16]}")
        except Exception:
            indicators.append("malwarebazaar_unavailable")
            break

    if not scores:
        return 0.0, indicators
    return _clamp(max(scores)), indicators


def _virustotal_hash_score(hashes: list[str]) -> tuple[float, list[str]]:
    if not settings.enable_virustotal_hash_lookup:
        return 0.0, []
    if not settings.virustotal_api_key:
        return 0.0, ["virustotal_hash_not_configured"]

    headers = {"x-apikey": settings.virustotal_api_key}
    scores: list[float] = []
    indicators: list[str] = []

    for file_hash in _limit_indicators(hashes):
        endpoint = f"https://www.virustotal.com/api/v3/files/{quote(file_hash, safe='')}"
        try:
            with httpx.Client(timeout=_request_timeout()) as client:
                response = client.get(endpoint, headers=headers)
                response.raise_for_status()
                stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = float(stats.get("malicious", 0.0) or 0.0)
            suspicious = float(stats.get("suspicious", 0.0) or 0.0)
            total = max(1.0, sum(float(v) for v in stats.values()))
            score = min(1.0, (malicious + (0.5 * suspicious)) / total)
            if score > 0.0:
                scores.append(score)
                indicators.append(
                    f"virustotal_hash_hit:{file_hash[:16]}:{int(malicious)}:{int(suspicious)}"
                )
        except Exception:
            indicators.append("virustotal_hash_unavailable")
            break

    if not scores:
        return 0.0, indicators
    return _clamp(max(scores)), indicators


def _external_enrichment_score(iocs: dict[str, list[str]]) -> tuple[float, list[str]]:
    domains = [str(item) for item in (iocs.get("domains") or [])]
    ips = [str(item) for item in (iocs.get("ips") or [])]
    hashes = [str(item) for item in (iocs.get("hashes") or [])]
    provider_scores: list[float] = []
    indicators: list[str] = []

    otx_score, otx_indicators = _otx_score(domains + ips + hashes)
    if otx_score > 0.0:
        provider_scores.append(otx_score)
    indicators.extend(otx_indicators)

    abuseipdb_score, abuseipdb_indicators = _abuseipdb_score(ips)
    if abuseipdb_score > 0.0:
        provider_scores.append(abuseipdb_score)
    indicators.extend(abuseipdb_indicators)

    malwarebazaar_score, malwarebazaar_indicators = _malwarebazaar_score(hashes)
    if malwarebazaar_score > 0.0:
        provider_scores.append(malwarebazaar_score)
    indicators.extend(malwarebazaar_indicators)

    vt_hash_score, vt_hash_indicators = _virustotal_hash_score(hashes)
    if vt_hash_score > 0.0:
        provider_scores.append(vt_hash_score)
    indicators.extend(vt_hash_indicators)

    if not provider_scores:
        return 0.0, indicators
    return _clamp(max(provider_scores)), indicators


def analyze(data: dict[str, Any]) -> dict[str, Any]:
    logger.info("Starting analysis", agent="threat_intel_agent")
    
    # Ensure offline DB is fresh and loaded
    ioc_count = _refresh_ioc_store_if_needed()
    
    # Aggregate candidates
    iocs = data.get("iocs", {}) or {}
    candidates = []
    candidates.extend(iocs.get("domains", []) or [])
    candidates.extend(iocs.get("ips", []) or [])
    candidates.extend(iocs.get("hashes", []) or [])

    # Fast offline SQLite lookup
    matches = _STORE.lookup(candidates)

    # ML Inference Pipeline
    agent_model = load_model()
    features = extract_features(data, matches, _STORE)
    prediction = predict(features, agent_model)
    
    # Build explanation indicators
    if matches:
        # Prefix with highest risk matching indicator (typically limit to 10 for log brevity)
        report_matches = [f"ioc_match:{m}" for m in matches[:10]]
    else:
        report_matches = ["no_local_ioc_hits"]

    external_score, external_indicators = _external_enrichment_score(iocs)
    total_candidates = len([item for item in candidates if str(item).strip()])
    local_match_score = _clamp(len(matches) / max(1, total_candidates))

    ml_risk = float(prediction.get("risk_score", 0.0) or 0.0)
    ml_confidence = float(prediction.get("confidence", 0.0) or 0.0)
    blended_risk = _clamp((0.55 * ml_risk) + (0.3 * local_match_score) + (0.15 * external_score))
    fused_risk = _clamp(max(ml_risk, local_match_score, external_score, blended_risk))
    confidence_floor = 0.55 + (0.2 if matches else 0.0) + (0.1 if external_score > 0.0 else 0.0)
    fused_confidence = _clamp(max(ml_confidence, confidence_floor))

    meta_indicators = [
        f"local_match_score={local_match_score}",
        f"external_enrichment_score={external_score}",
    ]
    if any(
        (
            settings.enable_otx_lookup,
            settings.enable_abuseipdb_lookup,
            settings.enable_malwarebazaar_lookup,
            settings.enable_virustotal_hash_lookup,
        )
    ):
        meta_indicators.append("external_threat_enrichment_enabled")
    else:
        meta_indicators.append("external_threat_enrichment_disabled")

    # Incorporate context into final response
    result = {
        "agent_name": "threat_intel_agent",
        "risk_score": fused_risk,
        "confidence": fused_confidence,
        "indicators": (report_matches + meta_indicators + external_indicators)[:20],
    }
    
    logger.info(
        "Analysis complete",
        risk_score=result["risk_score"],
        confidence=result["confidence"],
        matches=len(matches),
        ioc_count=ioc_count,
    )
    return result
