"""Threat intelligence agent backed by local IOC feed lookup."""

from __future__ import annotations

import csv
import functools
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from email_security.src.configs import settings
from email_security.src.services.logging_service import get_agent_logger

# Import the ML Pipeline components
from email_security.src.agents.threat_intel_agent.feature_extractor import extract_features
from email_security.src.agents.threat_intel_agent.model_loader import load_model
from email_security.src.agents.threat_intel_agent.inference import predict

logger = get_agent_logger("threat_intel_agent")

SQLITE_BUSY_TIMEOUT_MS = 30_000
SQLITE_SCHEMA_RETRIES = 6

IOC_SOURCE_ROOT = Path("datasets/threat_intelligence")
URL_FALLBACK_ROOT = Path("datasets/url_dataset/malicious")

# Curated static IOC seed list — always available regardless of feed state
from email_security.src.agents.threat_intel_agent.seed_iocs import SEED_IOCS


class IOCStore:
    """Persistent local IOC database backed by SQLite for fast membership checks."""

    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        if not self.db_path.is_absolute():
            self.db_path = Path(".") / self.db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()
        
        # Calculate max elements: roughly 10k strings per MB of cache
        max_cache_elements = max(1000, settings.cache_ioc_memory_size_mb * 10000)
        self.lookup_single = functools.lru_cache(maxsize=max_cache_elements)(self._lookup_single)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS};")
        return conn

    def _ensure_schema(self) -> None:
        for attempt in range(1, SQLITE_SCHEMA_RETRIES + 1):
            try:
                with self._connect() as conn:
                    # Configure SQLite durability/perf pragmas once at init time.
                    # Setting journal_mode repeatedly on each connection can contend
                    # with active writers and trigger transient "database is locked".
                    conn.execute("PRAGMA journal_mode=WAL;")
                    conn.execute("PRAGMA synchronous=NORMAL;")
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
                    conn.execute(
                        """
                        CREATE TABLE IF NOT EXISTS external_cache (
                            provider TEXT NOT NULL,
                            indicator TEXT NOT NULL,
                            score REAL NOT NULL,
                            indicators_json TEXT NOT NULL,
                            updated_ts INTEGER NOT NULL,
                            PRIMARY KEY (provider, indicator)
                        );
                        """
                    )
                    conn.commit()
                    return
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower() or attempt == SQLITE_SCHEMA_RETRIES:
                    raise
                sleep_seconds = 0.2 * attempt
                logger.warning(
                    "IOC schema init retry due to sqlite lock",
                    db_path=str(self.db_path),
                    attempt=attempt,
                    sleep_seconds=sleep_seconds,
                )
                time.sleep(sleep_seconds)

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

    def _lookup_single(self, indicator: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM iocs WHERE indicator = ?",
                (indicator,)
            ).fetchone()
            return row is not None

    def lookup(self, candidates: list[str]) -> list[str]:
        values = [str(item).strip().lower() for item in candidates if str(item).strip()]
        if not values:
            return []

        matches = []
        for val in values:
            if self.lookup_single(val):
                matches.append(val)
        return matches

    def clear_cache(self) -> None:
        self.lookup_single.cache_clear()

    def count(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()
            return int(row[0]) if row else 0

    def get_external_cache(
        self,
        provider: str,
        indicator: str,
        max_age_seconds: int | None,
    ) -> tuple[float, list[str]] | None:
        key_provider = str(provider).strip().lower()
        key_indicator = str(indicator).strip().lower()
        if not key_provider or not key_indicator:
            return None

        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT score, indicators_json, updated_ts
                FROM external_cache
                WHERE provider = ? AND indicator = ?
                """,
                (key_provider, key_indicator),
            ).fetchone()

        if not row:
            return None

        score = float(row[0] or 0.0)
        indicators_json = str(row[1] or "[]")
        updated_ts = int(row[2] or 0)
        if max_age_seconds is not None and updated_ts > 0:
            age = int(time.time()) - updated_ts
            if age > int(max_age_seconds):
                return None

        try:
            indicators = json.loads(indicators_json)
            if not isinstance(indicators, list):
                indicators = []
        except Exception:
            indicators = []
        return score, [str(item) for item in indicators]

    def set_external_cache(
        self,
        provider: str,
        indicator: str,
        score: float,
        indicators: list[str],
    ) -> None:
        key_provider = str(provider).strip().lower()
        key_indicator = str(indicator).strip().lower()
        if not key_provider or not key_indicator:
            return

        now = int(time.time())
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO external_cache(provider, indicator, score, indicators_json, updated_ts)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(provider, indicator)
                DO UPDATE SET
                  score = excluded.score,
                  indicators_json = excluded.indicators_json,
                  updated_ts = excluded.updated_ts
                """,
                (
                    key_provider,
                    key_indicator,
                    float(score),
                    json.dumps([str(item) for item in indicators]),
                    now,
                ),
            )
            conn.commit()


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
        from email_security.src.configs.settings import PROJECT_ROOT
        unified_path = PROJECT_ROOT / unified_path

    if not unified_path.exists():
        logger.warning(f"Unified IOC reference not found at {unified_path}. Falling back to source folders.")

    if unified_path.exists():
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
        except Exception as e:
            logger.error(f"Failed to read unified IOC reference: {e}")

    # Broaden IOC coverage with direct source-feed harvesting and URL fallback datasets.
    for root in (IOC_SOURCE_ROOT, URL_FALLBACK_ROOT):
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            suffix = path.suffix.lower()
            if suffix == ".csv":
                rows.extend(_read_csv_iocs(path))
            elif suffix == ".json":
                rows.extend(_read_json_iocs(path))
            elif suffix in {".txt", ".log", ".ioc"}:
                rows.extend(_read_txt_iocs(path))

    # Stable dedupe to reduce DB churn and preserve first source attribution.
    dedup: dict[str, tuple[str, str, str]] = {}
    for indicator, ioc_type, source in rows:
        key = str(indicator).strip().lower()
        if key and key not in dedup:
            dedup[key] = (key, str(ioc_type).strip().lower(), str(source).strip())
    return list(dedup.values())


_STORE = IOCStore(settings.ioc_db_path)

# Background refresh state — refresh is always run in a daemon thread so
# analyze() is never blocked by the slow feed-scan + bulk-upsert.
_refresh_lock = threading.Lock()
_refresh_in_progress = False


def _seed_store_if_empty() -> None:
    """Seed the IOC store with curated static entries if it is empty."""
    if _STORE.count() < 10:
        rows = [(indicator, ioc_type, "static_seed") for indicator, ioc_type in SEED_IOCS]
        seeded = _STORE.upsert_many(rows)
        logger.info("Seeded IOC store from curated static list", seeded=seeded)


# Seed on module load so the store is never empty
_seed_store_if_empty()


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


def _do_background_refresh() -> None:
    """Blocking refresh — always called from a background daemon thread."""
    global _refresh_in_progress
    try:
        now = int(time.time())
        harvested = _collect_iocs_from_feeds()
        upserted = _STORE.upsert_many(harvested)
        _STORE._set_last_refresh_ts(now)
        _STORE.clear_cache()
        total = _STORE.count()
        logger.info(
            "IOC store refreshed (background)",
            harvested=len(harvested),
            upserted=upserted,
            total=total,
            db_path=str(_STORE.db_path),
        )
    except Exception as exc:
        logger.warning("Background IOC refresh failed", error=str(exc))
    finally:
        with _refresh_lock:
            _refresh_in_progress = False


def _schedule_background_refresh_if_needed() -> None:
    """Check if a refresh is due; if so fire it off in a daemon thread.

    This function returns immediately — analyze() is never blocked.
    """
    global _refresh_in_progress
    now = int(time.time())
    last_refresh = _STORE.get_last_refresh_ts()
    if last_refresh and (now - last_refresh) < max(30, settings.ioc_refresh_seconds):
        return  # still fresh

    with _refresh_lock:
        if _refresh_in_progress:
            return  # already running
        _refresh_in_progress = True

    t = threading.Thread(target=_do_background_refresh, daemon=True, name="ioc-refresh")
    t.start()
    logger.info("IOC refresh scheduled in background thread")


def _refresh_ioc_store_if_needed() -> int:
    """Legacy synchronous call used by the API-layer periodic task only."""
    now = int(time.time())
    last_refresh = _STORE.get_last_refresh_ts()
    if last_refresh and (now - last_refresh) < max(30, settings.ioc_refresh_seconds):
        return _STORE.count()

    harvested = _collect_iocs_from_feeds()
    upserted = _STORE.upsert_many(harvested)
    _STORE._set_last_refresh_ts(now)
    _STORE.clear_cache()
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
    return max(1.0, min(3.0, float(settings.external_lookup_timeout_seconds)))


def _provider_time_budget_seconds() -> float:
    """Cap total wall time spent per external provider call chain.

    This keeps threat-intel analysis responsive under slow external APIs and
    prevents a single provider from stalling agent completion.
    """
    per_request = _request_timeout()
    return max(per_request, min(3.0, per_request * 1.5))


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

    started_at = time.monotonic()
    with httpx.Client(timeout=_request_timeout()) as client:
        for indicator in _limit_indicators(candidates):
            if (time.monotonic() - started_at) >= _provider_time_budget_seconds():
                indicators.append("otx_time_budget_exceeded")
                break

            indicator_type = _otx_indicator_type(indicator)
            cache_key = f"{indicator_type}:{indicator}"
            cached = _STORE.get_external_cache(
                provider="otx",
                indicator=cache_key,
                max_age_seconds=max(60, int(settings.external_lookup_cache_ttl_seconds)),
            )
            if cached is not None:
                cached_score, cached_indicators = cached
                if cached_score > 0.0:
                    scores.append(cached_score)
                indicators.extend(cached_indicators)
                continue

            endpoint = f"{base_url}/api/v1/indicators/{indicator_type}/{quote(indicator, safe='')}/general"
            try:
                response = client.get(endpoint, headers=headers)
                response.raise_for_status()
                payload = response.json()
                pulse_count = int((payload.get("pulse_info", {}) or {}).get("count", 0) or 0)
                provider_score = 0.0
                provider_indicators: list[str] = []
                if pulse_count > 0:
                    provider_score = min(1.0, 0.3 + (0.1 * pulse_count))
                    provider_indicators.append(f"otx_hit:{indicator_type.lower()}:{indicator}")
                _STORE.set_external_cache("otx", cache_key, provider_score, provider_indicators)
                if provider_score > 0.0:
                    scores.append(provider_score)
                indicators.extend(provider_indicators)
            except Exception:
                fallback = _STORE.get_external_cache("otx", cache_key, None)
                if fallback is not None:
                    fb_score, fb_indicators = fallback
                    if fb_score > 0.0:
                        scores.append(fb_score)
                    indicators.extend(fb_indicators)
                    indicators.append("otx_cache_fallback")
                    continue
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

    started_at = time.monotonic()
    with httpx.Client(timeout=_request_timeout()) as client:
        for ip in _limit_indicators(ips):
            if (time.monotonic() - started_at) >= _provider_time_budget_seconds():
                indicators.append("abuseipdb_time_budget_exceeded")
                break

            cached = _STORE.get_external_cache(
                provider="abuseipdb",
                indicator=ip,
                max_age_seconds=max(60, int(settings.external_lookup_cache_ttl_seconds)),
            )
            if cached is not None:
                cached_score, cached_indicators = cached
                if cached_score > 0.0:
                    scores.append(cached_score)
                indicators.extend(cached_indicators)
                continue

            params = {"ipAddress": ip, "maxAgeInDays": "90"}
            try:
                response = client.get(api_url, headers=headers, params=params)
                response.raise_for_status()
                payload = response.json().get("data", {}) or {}
                abuse_score = float(payload.get("abuseConfidenceScore", 0.0) or 0.0)
                normalized = _clamp(abuse_score / 100.0)
                provider_indicators: list[str] = []
                if normalized > 0.0:
                    scores.append(normalized)
                if abuse_score >= 25.0:
                    provider_indicators.append(f"abuseipdb_high_confidence:{ip}:{int(abuse_score)}")
                _STORE.set_external_cache("abuseipdb", ip, normalized, provider_indicators)
                indicators.extend(provider_indicators)
            except Exception:
                fallback = _STORE.get_external_cache("abuseipdb", ip, None)
                if fallback is not None:
                    fb_score, fb_indicators = fallback
                    if fb_score > 0.0:
                        scores.append(fb_score)
                    indicators.extend(fb_indicators)
                    indicators.append("abuseipdb_cache_fallback")
                    continue
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

    started_at = time.monotonic()
    with httpx.Client(timeout=_request_timeout()) as client:
        for file_hash in _limit_indicators(hashes):
            if (time.monotonic() - started_at) >= _provider_time_budget_seconds():
                indicators.append("malwarebazaar_time_budget_exceeded")
                break

            cached = _STORE.get_external_cache(
                provider="malwarebazaar",
                indicator=file_hash,
                max_age_seconds=max(60, int(settings.external_lookup_cache_ttl_seconds)),
            )
            if cached is not None:
                cached_score, cached_indicators = cached
                if cached_score > 0.0:
                    scores.append(cached_score)
                indicators.extend(cached_indicators)
                continue

            body = {"query": "get_info", "hash": file_hash}
            try:
                response = client.post(api_url, data=body)
                response.raise_for_status()
                payload = response.json()

                status = str(payload.get("query_status", "")).lower()
                provider_score = 0.0
                provider_indicators: list[str] = []
                if status == "ok" and payload.get("data"):
                    provider_score = 0.95
                    provider_indicators.append(f"malwarebazaar_hit:{file_hash[:16]}")
                _STORE.set_external_cache("malwarebazaar", file_hash, provider_score, provider_indicators)
                if provider_score > 0.0:
                    scores.append(provider_score)
                indicators.extend(provider_indicators)
            except httpx.HTTPStatusError as e:
                if e.response.status_code in {401, 403}:
                    fallback = _STORE.get_external_cache("malwarebazaar", file_hash, None)
                    if fallback is not None:
                        fb_score, fb_indicators = fallback
                        if fb_score > 0.0:
                            scores.append(fb_score)
                        indicators.extend(fb_indicators)
                        indicators.append("malwarebazaar_cache_fallback")
                        continue
                    indicators.append("malwarebazaar_unauthorized")
                else:
                    indicators.append("malwarebazaar_unavailable")
                break
            except Exception:
                fallback = _STORE.get_external_cache("malwarebazaar", file_hash, None)
                if fallback is not None:
                    fb_score, fb_indicators = fallback
                    if fb_score > 0.0:
                        scores.append(fb_score)
                    indicators.extend(fb_indicators)
                    indicators.append("malwarebazaar_cache_fallback")
                    continue
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

    started_at = time.monotonic()
    with httpx.Client(timeout=_request_timeout()) as client:
        for file_hash in _limit_indicators(hashes):
            if (time.monotonic() - started_at) >= _provider_time_budget_seconds():
                indicators.append("virustotal_hash_time_budget_exceeded")
                break

            cached = _STORE.get_external_cache(
                provider="virustotal_hash",
                indicator=file_hash,
                max_age_seconds=max(60, int(settings.external_lookup_cache_ttl_seconds)),
            )
            if cached is not None:
                cached_score, cached_indicators = cached
                if cached_score > 0.0:
                    scores.append(cached_score)
                indicators.extend(cached_indicators)
                continue

            endpoint = f"https://www.virustotal.com/api/v3/files/{quote(file_hash, safe='')}"
            try:
                response = client.get(endpoint, headers=headers)
                response.raise_for_status()
                stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = float(stats.get("malicious", 0.0) or 0.0)
                suspicious = float(stats.get("suspicious", 0.0) or 0.0)
                total = max(1.0, sum(float(v) for v in stats.values()))
                score = min(1.0, (malicious + (0.5 * suspicious)) / total)
                provider_indicators: list[str] = []
                if score > 0.0:
                    scores.append(score)
                    provider_indicators.append(
                        f"virustotal_hash_hit:{file_hash[:16]}:{int(malicious)}:{int(suspicious)}"
                    )
                _STORE.set_external_cache("virustotal_hash", file_hash, score, provider_indicators)
                indicators.extend(provider_indicators)
            except Exception:
                fallback = _STORE.get_external_cache("virustotal_hash", file_hash, None)
                if fallback is not None:
                    fb_score, fb_indicators = fallback
                    if fb_score > 0.0:
                        scores.append(fb_score)
                    indicators.extend(fb_indicators)
                    indicators.append("virustotal_hash_cache_fallback")
                    continue
                indicators.append("virustotal_hash_unavailable")
                break

    if not scores:
        return 0.0, indicators
    return _clamp(max(scores)), indicators


def _external_enrichment_score(iocs: dict[str, list[str]]) -> tuple[float, list[str]]:
    import signal
    domains = [str(item) for item in (iocs.get("domains") or [])]
    ips = [str(item) for item in (iocs.get("ips") or [])]
    hashes = [str(item) for item in (iocs.get("hashes") or [])]
    provider_scores: list[float] = []
    indicators: list[str] = []

    # Set global timeout for entire external enrichment to prevent agent from stalling
    enrichment_timeout_seconds = 5.0

    def timeout_handler(signum, frame):
        raise TimeoutError(f"External enrichment exceeded {enrichment_timeout_seconds}s budget")

    supports_alarm = hasattr(signal, "SIGALRM")
    old_handler = None

    try:
        if supports_alarm:
            old_handler = signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(int(enrichment_timeout_seconds) + 1)

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

        if supports_alarm:
            signal.alarm(0)
            if old_handler is not None:
                signal.signal(signal.SIGALRM, old_handler)
    except TimeoutError:
        logger.warning("External enrichment timeout; skipping for this analysis")
        indicators.append("external_enrichment_timeout")
        if supports_alarm:
            signal.alarm(0)
            if old_handler is not None:
                signal.signal(signal.SIGALRM, old_handler)
    except Exception as exc:
        logger.warning(f"External enrichment failed: {exc}")
        indicators.append("external_enrichment_error")
        if supports_alarm:
            signal.alarm(0)
            if old_handler is not None:
                signal.signal(signal.SIGALRM, old_handler)

    if not provider_scores:
        return 0.0, indicators
    return _clamp(max(provider_scores)), indicators


def analyze(data: dict[str, Any]) -> dict[str, Any]:
    logger.info("Starting analysis", agent="threat_intel_agent")

    # Schedule an IOC refresh in a daemon background thread if the store is stale.
    # This never blocks analyze() — we always query the live (or slightly stale) store.
    _schedule_background_refresh_if_needed()
    ioc_count = _STORE.count()

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
