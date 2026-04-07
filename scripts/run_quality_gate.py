#!/usr/bin/env python3
"""Run a focused quality gate and emit a timestamped validation report.

This script improves release readiness by collecting concrete pass/fail evidence
for core integration paths instead of relying on ad-hoc local runs.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ANALYSIS_ROOT = REPO_ROOT / "analysis_reports"

TEST_GROUPS = {
    "core_orchestrator": [
        "tests/test_langgraph_orchestrator.py",
        "tests/test_orchestrator_partial_finalization.py",
        "tests/test_operational_flow_e2e.py",
    ],
    "sandbox_safety": [
        "tests/test_sandbox_agent_behavior.py",
        "tests/test_sandbox_model_inference.py",
    ],
    "data_and_model_smoke": [
        "tests/test_content_preprocessing.py",
        "tests/test_url_model_smoke.py",
        "tests/test_attachment_ensemble_smoke.py",
        "tests/test_threat_intel_smoke.py",
        "tests/test_user_behavior_smoke.py",
    ],
}


def _run_pytest(paths: list[str]) -> dict[str, object]:
    cmd = [sys.executable, "-m", "pytest", "-q", *paths]
    started = datetime.now(timezone.utc)
    env = dict(os.environ)
    env["IOC_DB_PATH"] = str(REPO_ROOT / "data" / "ioc_store_ci.db")
    proc = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )
    finished = datetime.now(timezone.utc)
    return {
        "command": " ".join(cmd),
        "started_utc": started.isoformat(),
        "finished_utc": finished.isoformat(),
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "passed": proc.returncode == 0,
    }


def main() -> int:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_dir = ANALYSIS_ROOT / f"quality_gate_{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)

    results: dict[str, object] = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.executable,
        "groups": {},
    }

    overall_ok = True
    for group_name, group_tests in TEST_GROUPS.items():
        run = _run_pytest(group_tests)
        results["groups"][group_name] = run
        overall_ok = overall_ok and bool(run["passed"])

    results["overall_passed"] = overall_ok

    json_path = out_dir / "quality_gate_results.json"
    md_path = out_dir / "quality_gate_summary.md"
    json_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

    lines = [
        "# Quality Gate Summary",
        "",
        f"- Timestamp (UTC): `{results['timestamp_utc']}`",
        f"- Overall Passed: `{overall_ok}`",
        "",
        "## Groups",
    ]
    for group_name, run in results["groups"].items():
        status = "PASS" if run["passed"] else "FAIL"
        lines.append(f"- `{group_name}`: **{status}** (exit={run['exit_code']})")

    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"Quality gate report written to: {out_dir}")
    return 0 if overall_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
