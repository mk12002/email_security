"""Tests for sandbox preprocessing data normalization."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from email_security.preprocessing.sandbox_preprocessing import run


def test_sandbox_preprocessing_merges_sources(tmp_path: Path) -> None:
    base = tmp_path / "datasets"
    out = tmp_path / "datasets_processed"

    sandbox_dir = base / "sandbox_behavior"
    sandbox_dir.mkdir(parents=True)

    pd.DataFrame(
        [
            {
                "sample_id": "legacy_1",
                "file_extension": ".pdf",
                "executed": 1,
                "return_code": 0,
                "timed_out": 0,
                "spawned_processes": 1,
                "suspicious_process_count": 0,
                "file_entropy": 5.2,
                "label": 0,
            }
        ]
    ).to_csv(sandbox_dir / "sandbox_logs.csv", index=False)

    api_dir = sandbox_dir / "api_sequences"
    api_dir.mkdir(parents=True)
    pd.DataFrame(
        [
            {
                "sample_id": "api_1",
                "api_sequence": "CreateProcessW connect WriteFile",
                "label": "malware",
            }
        ]
    ).to_csv(api_dir / "oliveira_like.csv", index=False)

    cuckoo_dir = sandbox_dir / "cuckoo_reports"
    cuckoo_dir.mkdir(parents=True)
    report = {
        "info": {"score": 8.5},
        "target": {"file": {"name": "invoice.pdf", "entropy": 6.7}},
        "behavior": {
            "processes": [{"process_name": "invoice.pdf"}, {"process_name": "sh"}],
            "summary": {
                "connects": ["1.2.3.4"],
                "write_files": ["/tmp/a"],
                "executed_commands": ["/bin/sh -c curl http://x.y"]
            },
        },
        "network": {"hosts": ["1.2.3.4"], "http": [{"uri": "/"}]},
    }
    (cuckoo_dir / "report_1.json").write_text(json.dumps(report), encoding="utf-8")

    output_path = Path(run(base_dir=str(base), output_dir=str(out)))

    assert output_path.exists()
    frame = pd.read_csv(output_path)
    assert frame.shape[0] == 3
    assert {"sandbox_logs", "api_sequences", "cuckoo_reports"}.issubset(set(frame["source"].tolist()))
    assert {"connect_calls", "execve_calls", "file_write_calls", "label"}.issubset(set(frame.columns))

    audit_path = out / "sandbox_behavior_audit.json"
    assert audit_path.exists()
