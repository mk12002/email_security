"""Threat intelligence agent backed by local IOC feed lookup."""

from __future__ import annotations

import csv
import json
import sqlite3
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from configs.settings import settings
from services.logging_service import get_agent_logger

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
    rows: list[tuple[str, str, str]] = []

    for root in [IOC_SOURCE_ROOT, URL_FALLBACK_ROOT]:
        if not root.exists():
            continue
        for csv_file in root.rglob("*.csv"):
            rows.extend(_read_csv_iocs(csv_file))
        for json_file in root.rglob("*.json"):
            rows.extend(_read_json_iocs(json_file))
        for txt_file in root.rglob("*.txt"):
            rows.extend(_read_txt_iocs(txt_file))

    return rows


_STORE = IOCStore(settings.ioc_db_path)


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, round(value, 4)))


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


def analyze(data: dict[str, Any]) -> dict[str, Any]:
    logger.info("Starting analysis", agent="threat_intel_agent")
    ioc_count = _refresh_ioc_store_if_needed()
    iocs = data.get("iocs", {}) or {}
    candidates = []
    candidates.extend(iocs.get("domains", []) or [])
    candidates.extend(iocs.get("ips", []) or [])
    candidates.extend(iocs.get("hashes", []) or [])

    matches = _STORE.lookup(candidates)
    risk = min(1.0, 0.25 * len(matches))

    result = {
        "agent_name": "threat_intel_agent",
        "risk_score": _clamp(risk),
        "confidence": _clamp(0.4 if ioc_count == 0 else 0.85),
        "indicators": [f"ioc_match:{entry}" for entry in matches[:20]] or ["no_local_ioc_hits"],
    }
    logger.info(
        "Analysis complete",
        risk_score=result["risk_score"],
        matches=len(matches),
        ioc_count=ioc_count,
    )
    return result
