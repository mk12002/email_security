#!/usr/bin/env python3
"""Build a difficult test corpus for realistic stress testing.

Categories created:
- attachment_heavy_malware
- ioc_hit_phishing
- benign_high_link_marketing
- transactional_urgent_edge
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET_ROOT = REPO_ROOT.parent / "datasets" / "email_content"
IOC_UNIFIED = REPO_ROOT / "datasets_processed" / "threat_intel" / "unified_ioc_reference.csv"
OUTPUT_ROOT = REPO_ROOT / "email_drop" / "hard_set"

URL_RE = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE)

MARKETING_TOKENS = {
    "unsubscribe",
    "newsletter",
    "exclusive offer",
    "promotion",
    "best wishes",
    "contact me",
    "limited time",
}

TRANSACTIONAL_URGENT_TOKENS = {
    "invoice",
    "payment",
    "wire transfer",
    "reminder",
    "urgent",
    "account update",
}


@dataclass
class Candidate:
    source_path: Path
    label: str
    category_hits: list[str]
    attachment_markers: int
    url_count: int
    ioc_hits: int


def _label_for(path: Path) -> str:
    text = str(path).lower()
    if "/spam/" in text or "phish" in text or "mal" in text:
        return "malicious"
    if "/legitimate/" in text or "ham" in text:
        return "benign"
    return "unknown"


def _extract_domains(payload: str) -> set[str]:
    domains = {match.group(0).lower() for match in DOMAIN_RE.finditer(payload)}
    for url in URL_RE.findall(payload):
        host_match = re.search(r"https?://([^/:?#]+)", url, flags=re.IGNORECASE)
        if host_match:
            domains.add(host_match.group(1).lower())
    return {item.strip(".") for item in domains if item.strip(".")}


def _load_ioc_domains() -> set[str]:
    if not IOC_UNIFIED.exists():
        return set()

    domains: set[str] = set()
    with IOC_UNIFIED.open("r", encoding="utf-8", errors="ignore") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            ioc_type = str(row.get("ioc_type") or "").strip().lower()
            indicator = str(row.get("indicator") or "").strip().lower()
            if not indicator:
                continue
            if ioc_type in {"domain", "url"}:
                if ioc_type == "url":
                    host_match = re.search(r"https?://([^/:?#]+)", indicator, flags=re.IGNORECASE)
                    if host_match:
                        indicator = host_match.group(1).lower()
                domains.add(indicator.strip("."))
    return domains


def _score_candidate(path: Path, ioc_domains: set[str]) -> Candidate | None:
    try:
        payload = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return None

    lowered = payload.lower()
    label = _label_for(path)
    if label == "unknown":
        return None

    attachment_markers = sum(
        lowered.count(token)
        for token in (
            "content-disposition: attachment",
            "multipart/mixed",
            "filename=",
            "content-type: application/",
        )
    )
    urls = URL_RE.findall(payload)
    url_count = len(urls)
    domains = _extract_domains(payload)
    ioc_hits = len(domains & ioc_domains)

    category_hits: list[str] = []
    if label == "malicious" and attachment_markers >= 2:
        category_hits.append("attachment_heavy_malware")
    if label == "malicious" and ioc_hits >= 1:
        category_hits.append("ioc_hit_phishing")
    if label == "benign" and url_count >= 8 and any(token in lowered for token in MARKETING_TOKENS):
        category_hits.append("benign_high_link_marketing")
    if any(token in lowered for token in TRANSACTIONAL_URGENT_TOKENS):
        category_hits.append("transactional_urgent_edge")

    if not category_hits:
        return None

    return Candidate(
        source_path=path,
        label=label,
        category_hits=category_hits,
        attachment_markers=attachment_markers,
        url_count=url_count,
        ioc_hits=ioc_hits,
    )


def _all_eml_files(root: Path) -> list[Path]:
    return sorted(root.rglob("*.eml"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Build hard-set mail corpus for rigorous testing")
    parser.add_argument("--per-category", type=int, default=10, help="Max files per category")
    parser.add_argument("--apply", action="store_true", help="Copy selected files into email_drop/hard_set")
    args = parser.parse_args()

    ioc_domains = _load_ioc_domains()
    files = _all_eml_files(DATASET_ROOT)

    categories = {
        "attachment_heavy_malware": [],
        "ioc_hit_phishing": [],
        "benign_high_link_marketing": [],
        "transactional_urgent_edge": [],
    }

    for path in files:
        candidate = _score_candidate(path, ioc_domains)
        if not candidate:
            continue
        for category in candidate.category_hits:
            categories[category].append(candidate)

    selected: dict[str, list[Candidate]] = {}
    used: set[Path] = set()
    for category, items in categories.items():
        ranked = sorted(
            items,
            key=lambda c: (c.ioc_hits, c.attachment_markers, c.url_count),
            reverse=True,
        )
        chosen: list[Candidate] = []
        for item in ranked:
            if item.source_path in used:
                continue
            chosen.append(item)
            used.add(item.source_path)
            if len(chosen) >= max(1, int(args.per_category)):
                break
        selected[category] = chosen

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_dir = OUTPUT_ROOT / f"hard_set_{timestamp}"
    manifest_path = out_dir / "manifest.json"
    summary_path = out_dir / "summary.md"

    manifest: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_root": str(DATASET_ROOT),
        "ioc_unified_reference": str(IOC_UNIFIED),
        "per_category_target": int(args.per_category),
        "categories": {},
    }

    for category, items in selected.items():
        manifest["categories"][category] = [
            {
                "source_path": str(item.source_path),
                "label": item.label,
                "attachment_markers": item.attachment_markers,
                "url_count": item.url_count,
                "ioc_hits": item.ioc_hits,
            }
            for item in items
        ]

    if args.apply:
        out_dir.mkdir(parents=True, exist_ok=True)
        for category, items in selected.items():
            category_dir = out_dir / category
            category_dir.mkdir(parents=True, exist_ok=True)
            for item in items:
                shutil.copy2(item.source_path, category_dir / item.source_path.name)
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        lines = [
            "# Hard Set Summary",
            "",
            f"Generated: `{manifest['generated_at']}`",
            f"Source root: `{manifest['source_root']}`",
            f"Per-category target: `{manifest['per_category_target']}`",
            "",
            "## Category Counts",
        ]
        for category, items in selected.items():
            lines.append(f"- `{category}`: `{len(items)}`")
        summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"Found candidates from {len(files)} source emails")
    for category, items in selected.items():
        print(f"{category}: {len(items)} selected")
    if args.apply:
        print(f"OUTPUT_DIR={out_dir}")
        print(f"MANIFEST={manifest_path}")
        print(f"SUMMARY={summary_path}")
    else:
        print("Dry run complete. Re-run with --apply to copy files into hard_set.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
