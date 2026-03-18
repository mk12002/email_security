"""Sandbox behavior agent with ephemeral Docker detonation containers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import docker

from configs.settings import settings
from services.logging_service import get_agent_logger

logger = get_agent_logger("sandbox_agent")

RISKY_EXTENSIONS = {".exe", ".dll", ".js", ".ps1", ".docm", ".xlsm", ".hta", ".vbs", ".scr"}
SUSPICIOUS_PROCESS_TOKENS = {
    "powershell",
    "cmd.exe",
    "wscript",
    "cscript",
    "bash",
    "sh",
    "curl",
    "wget",
    "python",
    "perl",
}

DETONATION_SCRIPT = r'''
import json
import os
import subprocess
import time
from pathlib import Path


def snapshot_cmdlines():
    out = {}
    proc_root = Path("/proc")
    for pid_dir in proc_root.iterdir():
        if not pid_dir.name.isdigit():
            continue
        cmdline_file = pid_dir / "cmdline"
        try:
            raw = cmdline_file.read_bytes().replace(b"\x00", b" ").decode("utf-8", errors="ignore").strip()
            if raw:
                out[pid_dir.name] = raw
        except Exception:
            continue
    return out


target = os.environ.get("TARGET_FILE", "")
target_path = Path(target)
ext = target_path.suffix.lower()

run_cmd = None
if ext == ".py":
    run_cmd = ["python", str(target_path)]
elif ext == ".sh":
    run_cmd = ["sh", str(target_path)]
elif target_path.exists() and (os.access(str(target_path), os.X_OK) or ext in {".elf", ".bin", ".run", ".out"}):
    run_cmd = [str(target_path)]

baseline = snapshot_cmdlines()
spawned = []
timed_out = False
return_code = None
stdout_tail = ""
stderr_tail = ""

if run_cmd:
    try:
        proc = subprocess.Popen(run_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for _ in range(25):
            now = snapshot_cmdlines()
            for pid, cmd in now.items():
                if pid not in baseline:
                    spawned.append(cmd)
            if proc.poll() is not None:
                break
            time.sleep(1)

        if proc.poll() is None:
            timed_out = True
            proc.kill()

        out, err = proc.communicate(timeout=3)
        return_code = proc.returncode
        stdout_tail = (out or "")[-600:]
        stderr_tail = (err or "")[-600:]
    except Exception as exc:
        stderr_tail = str(exc)

result = {
    "executed": bool(run_cmd),
    "command": run_cmd,
    "return_code": return_code,
    "timed_out": timed_out,
    "spawned_processes": list(dict.fromkeys(spawned))[:40],
    "stdout_tail": stdout_tail,
    "stderr_tail": stderr_tail,
}
print(json.dumps(result))
'''


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, round(value, 4)))


def _safe_stop_remove(container) -> None:
    try:
        container.stop(timeout=2)
    except Exception:
        pass
    try:
        container.remove(force=True)
    except Exception:
        pass


def _parse_behavior(logs: str) -> dict[str, Any]:
    for line in reversed([entry.strip() for entry in logs.splitlines() if entry.strip()]):
        if line.startswith("{") and line.endswith("}"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    return {
        "executed": False,
        "command": None,
        "return_code": None,
        "timed_out": False,
        "spawned_processes": [],
        "stdout_tail": "",
        "stderr_tail": logs[-500:],
    }


def _detonate_attachment(docker_client, target: Path) -> tuple[float, list[str]]:
    detonation_target = f"/sample/{target.name}"
    container = docker_client.containers.run(
        image=settings.sandbox_detonation_image,
        command=["python", "-c", DETONATION_SCRIPT],
        detach=True,
        remove=False,
        volumes={str(target.parent): {"bind": "/sample", "mode": "ro"}},
        environment={"TARGET_FILE": detonation_target},
    )

    indicators: list[str] = []
    score = 0.0
    try:
        result = container.wait(timeout=settings.sandbox_timeout_seconds)
        logs = (container.logs(stdout=True, stderr=True) or b"").decode("utf-8", errors="replace")
        behavior = _parse_behavior(logs)

        if behavior.get("executed"):
            score += 0.08
            indicators.append(f"detonation_executed:{target.name}")

        return_code = behavior.get("return_code")
        if isinstance(return_code, int) and return_code != 0:
            score += 0.12
            indicators.append(f"detonation_nonzero_exit:{target.name}")

        if behavior.get("timed_out"):
            score += 0.1
            indicators.append(f"detonation_timeout:{target.name}")

        spawned = [str(item).lower() for item in behavior.get("spawned_processes", []) if str(item).strip()]
        if len(spawned) >= 3:
            score += 0.15
            indicators.append(f"process_fanout:{target.name}")

        suspicious_hits = 0
        for proc in spawned:
            if any(token in proc for token in SUSPICIOUS_PROCESS_TOKENS):
                suspicious_hits += 1
                if suspicious_hits <= 3:
                    indicators.append(f"suspicious_process_spawn:{target.name}")
        score += min(0.36, 0.12 * suspicious_hits)

        stderr_tail = str(behavior.get("stderr_tail") or "").lower()
        if any(token in stderr_tail for token in ["permission denied", "not found", "exec format", "operation not permitted"]):
            score += 0.08
            indicators.append(f"sandbox_execution_anomaly:{target.name}")

        if result.get("StatusCode", 0) not in (0,):
            score += 0.05
            indicators.append(f"container_nonzero_status:{target.name}")

    finally:
        _safe_stop_remove(container)

    return _clamp(score), indicators


def analyze(data: dict[str, Any]) -> dict[str, Any]:
    logger.info("Starting analysis", agent="sandbox_agent")
    attachments = data.get("attachments", []) or []
    if not attachments:
        return {
            "agent_name": "sandbox_agent",
            "risk_score": 0.0,
            "confidence": 0.75,
            "indicators": ["no_attachments_for_sandbox"],
        }

    indicators: list[str] = []
    risk = 0.0

    try:
        docker_client = docker.from_env()
        for attachment in attachments[:3]:
            target = Path(attachment.get("path", ""))
            if not target.exists():
                indicators.append(f"missing_attachment_path:{attachment.get('filename', 'unknown')}")
                continue

            detonation_score, detonation_indicators = _detonate_attachment(docker_client, target)
            risk += detonation_score
            indicators.extend(detonation_indicators)

            if target.suffix.lower() in RISKY_EXTENSIONS:
                risk += 0.12
                indicators.append(f"risky_executable_attachment:{target.name}")

    except Exception as exc:
        indicators.append("docker_sandbox_unavailable")
        logger.warning("Sandbox unavailable, falling back to static behavior hints", error=str(exc))
        for attachment in attachments[:5]:
            filename = (attachment.get("filename") or "").lower()
            if any(token in filename for token in ["invoice", "payment", "urgent", "update"]):
                risk += 0.08
                indicators.append(f"suspicious_attachment_name:{filename}")

    result = {
        "agent_name": "sandbox_agent",
        "risk_score": _clamp(risk),
        "confidence": _clamp(0.45 if "docker_sandbox_unavailable" in indicators else 0.82),
        "indicators": indicators[:20],
    }
    logger.info("Analysis complete", risk_score=result["risk_score"])
    return result
