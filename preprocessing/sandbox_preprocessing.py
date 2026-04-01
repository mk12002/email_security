"""Sandbox behavior preprocessing for API-sequence and Cuckoo-style datasets."""

from __future__ import annotations

import json
import math
import re
from pathlib import Path

import pandas as pd

WORKSPACE_ROOT = Path(__file__).resolve().parents[2]

SHELL_MARKERS = {"sh", "bash", "zsh", "cmd", "powershell", "pwsh"}


def _resolve_input_dir(path_value: str) -> Path:
    path = Path(path_value)
    if path.is_absolute():
        return path
    if path.exists():
        return path
    return WORKSPACE_ROOT / path


def _resolve_output_dir(path_value: str) -> Path:
    path = Path(path_value)
    if path.is_absolute():
        return path
    return WORKSPACE_ROOT / path


def _as_int(value: object, default: int = 0) -> int:
    try:
        if value is None:
            return default
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return default


def _as_float(value: object, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def _label_to_int(value: object) -> int | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"1", "true", "malicious", "malware", "bad", "yes"}:
        return 1
    if text in {"0", "false", "benign", "good", "no"}:
        return 0
    return None


def _extract_label(row: dict[str, object]) -> int:
    for key in ("label", "class", "family", "is_malware", "malicious"):
        if key in row:
            maybe = _label_to_int(row.get(key))
            if maybe is not None:
                return maybe
    return 1


def _entropy_from_tokens(tokens: list[str]) -> float:
    if not tokens:
        return 0.0
    joined = " ".join(tokens)
    counts: dict[str, int] = {}
    for ch in joined:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(joined)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 2)


def _split_api_sequence(raw: object) -> list[str]:
    if raw is None:
        return []
    text = str(raw).strip()
    if not text:
        return []
    parts = [p.strip() for p in re.split(r"[\s,;|>]+", text) if p.strip()]
    return parts


def _normalize_row(row: dict[str, object], source: str, sample_id: str) -> dict[str, object]:
    return {
        "sample_id": sample_id,
        "file_extension": str(row.get("file_extension") or row.get("ext") or "unknown"),
        "executed": _as_int(row.get("executed"), 1),
        "return_code": _as_int(row.get("return_code"), 0),
        "timed_out": _as_int(row.get("timed_out"), 0),
        "spawned_processes": _as_int(row.get("spawned_processes"), 0),
        "suspicious_process_count": _as_int(row.get("suspicious_process_count"), 0),
        "file_entropy": _as_float(row.get("file_entropy"), 0.0),
        "connect_calls": _as_int(row.get("connect_calls"), 0),
        "execve_calls": _as_int(row.get("execve_calls"), 0),
        "file_write_calls": _as_int(row.get("file_write_calls"), 0),
        "label": _extract_label(row),
        "source": source,
    }


def _load_existing_sandbox_logs(base_dir: Path) -> list[dict[str, object]]:
    csv_path = base_dir / "sandbox_behavior" / "sandbox_logs.csv"
    if not csv_path.exists() or csv_path.stat().st_size == 0:
        return []

    rows: list[dict[str, object]] = []
    df = pd.read_csv(csv_path)
    for idx, row in df.fillna("").iterrows():
        as_dict = row.to_dict()
        sample_id = str(as_dict.get("sample_id") or f"synthetic_{idx:06d}")
        rows.append(_normalize_row(as_dict, "sandbox_logs", sample_id))
    return rows


def _load_api_sequences(base_dir: Path) -> list[dict[str, object]]:
    api_dir = base_dir / "sandbox_behavior" / "api_sequences"
    if not api_dir.exists():
        return []

    rows: list[dict[str, object]] = []
    candidate_files = sorted(api_dir.rglob("*.csv"))
    for file_path in candidate_files:
        try:
            frame = pd.read_csv(file_path)
        except Exception:
            continue

        col_map = {str(c).lower(): c for c in frame.columns}
        sequence_col = None
        for key in ("api_sequence", "api_calls", "sequence", "calls"):
            if key in col_map:
                sequence_col = col_map[key]
                break
        if sequence_col is None:
            continue

        for idx, row in frame.fillna("").iterrows():
            sequence = _split_api_sequence(row.get(sequence_col))
            lowered = [item.lower() for item in sequence]
            execve_calls = sum(1 for item in lowered if "exec" in item or "createprocess" in item)
            connect_calls = sum(1 for item in lowered if "connect" in item or "socket" in item or "internet" in item)
            file_write_calls = sum(
                1
                for item in lowered
                if "write" in item or "createfile" in item or "open" in item or "rename" in item
            )
            suspicious = 1 if any(marker in lowered for marker in SHELL_MARKERS) else 0

            row_dict = row.to_dict()
            label = _extract_label(row_dict)
            sample_id = str(row_dict.get("sample_id") or f"api_{file_path.stem}_{idx:06d}")
            normalized = _normalize_row(
                {
                    "file_extension": row_dict.get("file_extension", "unknown"),
                    "executed": 1,
                    "return_code": row_dict.get("return_code", 0),
                    "timed_out": row_dict.get("timed_out", 0),
                    "spawned_processes": row_dict.get("spawned_processes", max(execve_calls, suspicious)),
                    "suspicious_process_count": row_dict.get("suspicious_process_count", suspicious),
                    "file_entropy": row_dict.get("file_entropy", _entropy_from_tokens(sequence)),
                    "connect_calls": connect_calls,
                    "execve_calls": execve_calls,
                    "file_write_calls": file_write_calls,
                    "label": label,
                },
                source="api_sequences",
                sample_id=sample_id,
            )
            rows.append(normalized)
    return rows


def _load_cuckoo_reports(base_dir: Path) -> list[dict[str, object]]:
    report_dir = base_dir / "sandbox_behavior" / "cuckoo_reports"
    if not report_dir.exists():
        return []

    rows: list[dict[str, object]] = []
    for file_path in sorted(report_dir.rglob("*.json")):
        try:
            report = json.loads(file_path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue

        behavior = report.get("behavior", {}) if isinstance(report, dict) else {}
        summary = behavior.get("summary", {}) if isinstance(behavior, dict) else {}
        processes = behavior.get("processes", []) if isinstance(behavior, dict) else []
        network = report.get("network", {}) if isinstance(report, dict) else {}

        process_count = len(processes) if isinstance(processes, list) else 0
        connect_calls = 0
        execve_calls = 0
        file_write_calls = 0
        suspicious = 0

        if isinstance(summary, dict):
            connect_calls += len(summary.get("connects", []) or [])
            connect_calls += len(summary.get("resolved_apis", []) or [])
            file_write_calls += len(summary.get("write_files", []) or [])
            file_write_calls += len(summary.get("files", []) or [])
            execve_calls += len(summary.get("executed_commands", []) or [])
            commands = [str(c).lower() for c in (summary.get("executed_commands", []) or [])]
            if any(any(marker in cmd for marker in SHELL_MARKERS) for cmd in commands):
                suspicious += 1

        if isinstance(network, dict):
            connect_calls += len(network.get("hosts", []) or [])
            connect_calls += len(network.get("domains", []) or [])
            connect_calls += len(network.get("http", []) or [])
            connect_calls += len(network.get("tcp", []) or [])
            connect_calls += len(network.get("udp", []) or [])

        target = report.get("target", {}) if isinstance(report, dict) else {}
        file_info = target.get("file", {}) if isinstance(target, dict) else {}
        name = str(file_info.get("name") or file_path.stem)
        ext = "." + name.split(".")[-1] if "." in name else "unknown"

        labels = report.get("info", {}) if isinstance(report, dict) else {}
        score = _as_float(labels.get("score"), 0.0) if isinstance(labels, dict) else 0.0
        label = 1 if score >= 6.0 else 0

        rows.append(
            _normalize_row(
                {
                    "file_extension": ext,
                    "executed": 1,
                    "return_code": 0,
                    "timed_out": 0,
                    "spawned_processes": process_count,
                    "suspicious_process_count": suspicious,
                    "file_entropy": _as_float(file_info.get("entropy"), 0.0),
                    "connect_calls": connect_calls,
                    "execve_calls": max(execve_calls, process_count - 1),
                    "file_write_calls": file_write_calls,
                    "label": label,
                },
                source="cuckoo_reports",
                sample_id=f"cuckoo_{file_path.stem}",
            )
        )
    return rows


def run(base_dir: str = "datasets", output_dir: str = "datasets_processed") -> str:
    base = _resolve_input_dir(base_dir)
    output = _resolve_output_dir(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    rows: list[dict[str, object]] = []
    rows.extend(_load_existing_sandbox_logs(base))
    rows.extend(_load_api_sequences(base))
    rows.extend(_load_cuckoo_reports(base))

    if not rows:
        raise FileNotFoundError(
            "No sandbox behavior sources found. Expected at least one of: "
            "datasets/sandbox_behavior/sandbox_logs.csv, "
            "datasets/sandbox_behavior/api_sequences/*.csv, "
            "datasets/sandbox_behavior/cuckoo_reports/*.json"
        )

    frame = pd.DataFrame(rows)
    frame = frame.drop_duplicates(subset=["sample_id", "source"], keep="first")
    frame["label"] = frame["label"].astype(int)

    out_csv = output / "sandbox_behavior_training.csv"
    frame.to_csv(out_csv, index=False)

    audit = {
        "rows": int(frame.shape[0]),
        "malicious": int((frame["label"] == 1).sum()),
        "benign": int((frame["label"] == 0).sum()),
        "sources": frame["source"].value_counts().to_dict(),
        "output": str(out_csv),
    }
    (output / "sandbox_behavior_audit.json").write_text(json.dumps(audit, indent=2), encoding="utf-8")

    return str(out_csv)


if __name__ == "__main__":
    out = run(base_dir="datasets", output_dir="datasets_processed")
    print(out)
