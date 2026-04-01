"""Sandbox behavior agent with Create -> Detonate -> Monitor -> Destroy lifecycle."""

from __future__ import annotations

import csv
import io
import math
import re
import shlex
import tarfile
import time
from pathlib import Path
from typing import Any

import docker
from docker.errors import DockerException, ImageNotFound, NotFound

from configs.settings import settings
from services.logging_service import get_agent_logger

logger = get_agent_logger("sandbox_agent")

RISKY_EXTENSIONS = {
    ".exe",
    ".dll",
    ".js",
    ".ps1",
    ".docm",
    ".xlsm",
    ".hta",
    ".vbs",
    ".scr",
}
SHELL_TOKENS = {"/bin/sh", "sh", "/bin/bash", "bash", "cmd.exe", "powershell"}
NETWORK_TOOL_TOKENS = {"curl", "wget", "powershell", "python", "perl"}
SENSITIVE_DIRS = ("/etc", "/bin", "/usr", "/root", "/var", "/home")
WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
SANDBOX_RUNTIME_CSV = WORKSPACE_ROOT / "datasets" / "sandbox_behavior" / "runtime_observations.csv"

EXECVE_RE = re.compile(r"execve\(\"(?P<exe>[^\"]+)\"(?:,\s*\[(?P<argv>.*?)\])?")
CONNECT_RE = re.compile(r"sin_addr=inet_addr\(\"(?P<ip>\d+\.\d+\.\d+\.\d+)\"\)", re.IGNORECASE)
OPEN_WRITE_RE = re.compile(
    r"(?:open|openat)\([^\"]*\"(?P<path>/[^\"]+)\"[^\n]*O_(?:WRONLY|RDWR|CREAT|TRUNC)",
    re.IGNORECASE,
)


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, round(value, 4)))


def _safe_stop_remove(container: Any) -> None:
    try:
        container.stop(timeout=2)
    except Exception:
        pass
    try:
        container.remove(force=True)
    except Exception:
        pass


def _is_private_ip(ip: str) -> bool:
    if ip.startswith("10.") or ip.startswith("127."):
        return True
    if ip.startswith("192.168."):
        return True
    if ip.startswith("169.254."):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".", 2)[1])
            return 16 <= second <= 31
        except Exception:
            return False
    return False


def _build_tar_bytes(src: Path, dst_name: str) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        payload = src.read_bytes()
        info = tarfile.TarInfo(name=dst_name)
        info.size = len(payload)
        info.mode = 0o644
        info.mtime = int(time.time())
        tar.addfile(info, io.BytesIO(payload))
    buffer.seek(0)
    return buffer.read()


def _file_entropy(path: Path) -> float:
    data = path.read_bytes()
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    entropy = 0.0
    total = len(data)
    for count in counts:
        if not count:
            continue
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 2)


def _derive_training_row(
    *,
    target: Path,
    signals: dict[str, Any],
    timed_out: bool,
    exit_code: int,
    risk_score: float,
) -> dict[str, Any]:
    exec_chain = signals.get("exec_chain", []) or []
    lowered_exec = [str(item).lower() for item in exec_chain]
    shell_count = sum(1 for exe in lowered_exec if any(token in exe for token in SHELL_TOKENS))
    network_tool_count = sum(1 for exe in lowered_exec if any(token in exe for token in NETWORK_TOOL_TOKENS))
    suspicious_process_count = shell_count + network_tool_count

    if signals.get("critical_chain_detected"):
        suspicious_process_count += 1

    row = {
        "sample_id": f"runtime_{int(time.time() * 1000)}_{target.stem}",
        "file_extension": target.suffix.lower() or "unknown",
        "executed": 1,
        "return_code": int(exit_code),
        "timed_out": int(timed_out),
        "spawned_processes": max(len(exec_chain), 0),
        "suspicious_process_count": suspicious_process_count,
        "file_entropy": _file_entropy(target),
        "connect_calls": len(signals.get("remote_ips", []) or []),
        "execve_calls": len(exec_chain),
        "file_write_calls": len(signals.get("sensitive_writes", []) or []),
        "critical_chain_detected": int(bool(signals.get("critical_chain_detected"))),
        "behavior_risk_score": _clamp(risk_score),
        # Weak-supervision bootstrap: keep as pseudo-label until SOC verdict is joined.
        "label": int(risk_score >= 0.86),
        "source": "runtime_detonation",
        "filename": target.name,
    }
    return row


def _append_runtime_observation(row: dict[str, Any]) -> None:
    SANDBOX_RUNTIME_CSV.parent.mkdir(parents=True, exist_ok=True)
    columns = [
        "sample_id",
        "filename",
        "file_extension",
        "executed",
        "return_code",
        "timed_out",
        "spawned_processes",
        "suspicious_process_count",
        "file_entropy",
        "connect_calls",
        "execve_calls",
        "file_write_calls",
        "critical_chain_detected",
        "behavior_risk_score",
        "label",
        "source",
    ]
    file_exists = SANDBOX_RUNTIME_CSV.exists()
    with SANDBOX_RUNTIME_CSV.open("a", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns)
        if not file_exists:
            writer.writeheader()
        writer.writerow({col: row.get(col, "") for col in columns})


def _choose_exec_command(sample_path: str, ext: str) -> str:
    quoted = shlex.quote(sample_path)
    if ext == ".py":
        return f"python3 {quoted}"
    if ext in {".sh", ".bash"}:
        return f"sh {quoted}"
    if ext in {".js", ".mjs"}:
        return f"node {quoted}"
    if ext in {".pl"}:
        return f"perl {quoted}"
    return quoted


def _extract_behavior_from_strace(logs: str) -> dict[str, Any]:
    exec_chain: list[str] = []
    remote_ips: list[str] = []
    sensitive_writes: list[str] = []

    for line in logs.splitlines():
        exec_match = EXECVE_RE.search(line)
        if exec_match:
            exe = exec_match.group("exe")
            if exe:
                exec_chain.append(exe)

        connect_match = CONNECT_RE.search(line)
        if connect_match:
            ip = connect_match.group("ip")
            if ip and not _is_private_ip(ip):
                remote_ips.append(ip)

        write_match = OPEN_WRITE_RE.search(line)
        if write_match:
            path = write_match.group("path")
            if path and path.startswith(SENSITIVE_DIRS):
                sensitive_writes.append(path)

    unique_exec_chain = list(dict.fromkeys(exec_chain))[:32]
    unique_remote_ips = list(dict.fromkeys(remote_ips))[:16]
    unique_sensitive_writes = list(dict.fromkeys(sensitive_writes))[:16]

    lowered_exec = [item.lower() for item in unique_exec_chain]
    shell_spawned = any(any(token in exe for token in SHELL_TOKENS) for exe in lowered_exec)
    network_tool_spawned = any(any(token in exe for token in NETWORK_TOOL_TOKENS) for exe in lowered_exec)
    critical_chain_detected = shell_spawned and (network_tool_spawned or bool(unique_remote_ips))

    return {
        "exec_chain": unique_exec_chain,
        "remote_ips": unique_remote_ips,
        "sensitive_writes": unique_sensitive_writes,
        "shell_spawned": shell_spawned,
        "network_tool_spawned": network_tool_spawned,
        "critical_chain_detected": critical_chain_detected,
    }


def _score_behavior_signals(signals: dict[str, Any], timed_out: bool, nonzero_exit: bool) -> tuple[float, list[str]]:
    score = 0.0
    indicators: list[str] = []

    if signals.get("exec_chain"):
        score += 0.12
        indicators.append("sandbox_exec_activity")

    if signals.get("shell_spawned"):
        score += 0.5
        indicators.append("shell_spawn_detected")

    remote_ips = signals.get("remote_ips", []) or []
    if remote_ips:
        score += 0.45
        indicators.append("remote_connect_detected")

    writes = signals.get("sensitive_writes", []) or []
    if writes:
        score += 0.25
        indicators.append("sensitive_fs_modification")

    if signals.get("critical_chain_detected"):
        score += 0.2
        indicators.append("critical_chain_detected")

    if timed_out:
        score += 0.1
        indicators.append("detonation_timeout")

    if nonzero_exit:
        score += 0.06
        indicators.append("nonzero_exit_status")

    score = _clamp(score)
    if signals.get("shell_spawned") or remote_ips:
        score = max(score, 0.86)

    return score, indicators


def _detonate_attachment(docker_client: Any, target: Path) -> tuple[float, list[str], dict[str, Any], dict[str, Any]]:
    image = settings.sandbox_detonation_image
    timeout_seconds = int(settings.sandbox_timeout_seconds)
    sample_name = f"sample{target.suffix.lower() or '.bin'}"
    sample_path = f"/sandbox/input/{sample_name}"
    ext = target.suffix.lower()

    try:
        docker_client.images.get(image)
    except ImageNotFound:
        docker_client.images.pull(image)

    container = docker_client.containers.create(
        image=image,
        command=["sh", "-lc", "while true; do sleep 1; done"],
        detach=True,
        remove=False,
        working_dir="/sandbox",
    )

    indicators: list[str] = []
    behavior: dict[str, Any] = {
        "exec_chain": [],
        "remote_ips": [],
        "sensitive_writes": [],
        "shell_spawned": False,
        "network_tool_spawned": False,
        "critical_chain_detected": False,
    }

    timed_out = False
    nonzero_exit = False
    exit_code = 0

    try:
        container.start()
        container.exec_run(["mkdir", "-p", "/sandbox/input", "/sandbox/output"], stdout=False, stderr=False)

        archive = _build_tar_bytes(target, sample_name)
        container.put_archive(path="/sandbox/input", data=archive)

        detonation_cmd = _choose_exec_command(sample_path=sample_path, ext=ext)
        shell_cmd = (
            f"set -e; "
            f"chmod +x {shlex.quote(sample_path)} || true; "
            f"timeout {max(2, timeout_seconds - 2)}s "
            f"strace -f -tt -s 256 -e trace=process,network,file {detonation_cmd}"
        )

        started = time.monotonic()
        exec_result = container.exec_run(["sh", "-lc", shell_cmd], detach=True)
        exec_id = exec_result.output.decode("utf-8", errors="ignore") if isinstance(exec_result.output, (bytes, bytearray)) else str(exec_result.output)

        # Poll exec status with short sleeps so the monitor loop remains responsive.
        while True:
            status = docker_client.api.exec_inspect(exec_id)
            if not status.get("Running", False):
                exit_code = int(status.get("ExitCode", 0) or 0)
                nonzero_exit = exit_code != 0
                break
            if time.monotonic() - started > timeout_seconds:
                timed_out = True
                try:
                    container.kill()
                except Exception:
                    pass
                break
            time.sleep(0.2)

        raw_logs = (container.logs(stdout=True, stderr=True) or b"").decode("utf-8", errors="replace")
        behavior = _extract_behavior_from_strace(raw_logs)

        score, score_indicators = _score_behavior_signals(
            signals=behavior,
            timed_out=timed_out,
            nonzero_exit=nonzero_exit,
        )
        indicators.extend(score_indicators)

        training_row = _derive_training_row(
            target=target,
            signals=behavior,
            timed_out=timed_out,
            exit_code=exit_code,
            risk_score=score,
        )
        _append_runtime_observation(training_row)

        return score, indicators, behavior, training_row

    finally:
        _safe_stop_remove(container)


def _should_detonate(attachment: dict[str, Any], target: Path) -> bool:
    static_score = attachment.get("static_score", attachment.get("static_risk_score"))
    if isinstance(static_score, (int, float)) and float(static_score) > 0.6:
        return True
    return target.suffix.lower() in RISKY_EXTENSIONS


def analyze(data: dict[str, Any]) -> dict[str, Any]:
    logger.info("Starting analysis", agent="sandbox_agent")
    attachments = data.get("attachments", []) or []
    if not attachments:
        return {
            "agent_name": "sandbox_agent",
            "risk_score": 0.0,
            "behavior_risk_score": 0.0,
            "confidence": 0.75,
            "indicators": ["no_attachments_for_sandbox"],
            "behavior_summary": {},
        }

    risk = 0.0
    indicators: list[str] = []
    behavior_summary: dict[str, Any] = {}

    try:
        docker_client = docker.from_env()
        for attachment in attachments[:3]:
            target = Path(attachment.get("path", ""))
            if not target.exists():
                indicators.append(f"missing_attachment_path:{attachment.get('filename', 'unknown')}")
                continue

            if not _should_detonate(attachment, target):
                indicators.append(f"sandbox_skipped_low_suspicion:{target.name}")
                continue

            detonation_score, detonation_indicators, behavior, training_row = _detonate_attachment(docker_client, target)
            risk += detonation_score
            indicators.extend([f"{indicator}:{target.name}" for indicator in detonation_indicators])
            behavior_summary[target.name] = behavior
            behavior_summary[target.name]["derived_training_row"] = training_row

            if target.suffix.lower() in RISKY_EXTENSIONS:
                risk += 0.08
                indicators.append(f"risky_executable_attachment:{target.name}")

    except (DockerException, NotFound, OSError) as exc:
        indicators.append("docker_sandbox_unavailable")
        logger.warning("Sandbox unavailable, falling back to static behavior hints", error=str(exc))
        for attachment in attachments[:5]:
            filename = str(attachment.get("filename") or "").lower()
            if any(token in filename for token in ["invoice", "payment", "urgent", "update"]):
                risk += 0.08
                indicators.append(f"suspicious_attachment_name:{filename}")

    final_risk = _clamp(risk)
    result = {
        "agent_name": "sandbox_agent",
        "risk_score": final_risk,
        "behavior_risk_score": final_risk,
        "confidence": _clamp(0.45 if "docker_sandbox_unavailable" in indicators else 0.86),
        "indicators": indicators[:30],
        "behavior_summary": behavior_summary,
    }
    logger.info("Analysis complete", risk_score=result["risk_score"])
    return result
