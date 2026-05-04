"""
Base FastAPI application for the Agentic Email Security System.

Exposes health check and email analysis endpoints.
This service will be extended in later phases with full agent orchestration.
"""

import base64
import binascii
import asyncio
import hashlib
import ipaddress
import re
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
import tempfile
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI
from fastapi import Depends, File, Header, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from loguru import logger
import psycopg2
import redis.asyncio as redis_async

from email_security.api.schemas import (
    AgentDirectTestRequest,
    AgentDirectTestResponse,
    EmailAnalysisRequest,
    EmailAnalysisResponse,
    HealthResponse,
)
from email_security.configs.settings import settings
from email_security.services.email_parser import EmailParserService
from email_security.services.logging_service import setup_logging
from email_security.services.messaging_service import RabbitMQClient


URL_REGEX = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

SUPPORTED_AGENT_TESTS = [
    "header_agent",
    "content_agent",
    "url_agent",
    "attachment_agent",
    "sandbox_agent",
    "threat_intel_agent",
    "user_behavior_agent",
]

AGENT_TEST_EXAMPLES: dict[str, dict[str, Any]] = {
    "header_agent": {
        "headers": {
            "sender": "admin@rnicrosoft.com",
            "reply_to": "hacker@evil.example",
            "subject": "Urgent: verify your account",
            "received": [
                "from mx.github.com by smtp.gmail.com",
                "from internal by mx.github.com"
            ],
            "message_id": "<m-header-1>",
            "authentication_results": "spf=fail; dkim=fail; dmarc=fail",
        }
    },
    "content_agent": {
        "headers": {"subject": "URGENT: Final Notice - Invoice Overdue"},
        "body": {
            "plain": "Dear Customer, your account is past due. If you do not click the link below to process your payment within 24 hours, your services will be terminated and legal action will be taken. Act immediately.",
            "html": ""
        }
    },
    "url_agent": {
        "urls": [
            "http://secure-login-paypa1.example/verify",
            "https://microsoft.com-security-login.example/reset?token=123",
            "https://google.com"
        ]
    },
    "attachment_agent": {
        "attachments": [
            {
                "filename": "invoice_urgent.exe",
                "content_type": "application/x-msdownload",
                "size_bytes": 145760,
                "path": "/tmp/invoice_urgent.exe",  # nosec B108
            },
            {
                "filename": "meeting_notes.txt",
                "content_type": "text/plain",
                "size_bytes": 2048,
                "path": "/tmp/meeting_notes.txt",  # nosec B108
            }
        ]
    },
    "sandbox_agent": {
        "attachments": [
            {
                "filename": "payload.docm",
                "content_type": "application/vnd.ms-word.document.macroEnabled.12",
                "size_bytes": 40960,
                "path": "/tmp/payload.docm",  # nosec B108
            },
            {
                "filename": "summary.pdf",
                "content_type": "application/pdf",
                "size_bytes": 10240,
                "path": "/tmp/summary.pdf",  # nosec B108
            }
        ]
    },
    "threat_intel_agent": {
        "headers": {"sender": "attacker@evil.example"},
        "urls": ["http://known-bad.example/phish", "https://github.com"],
        "iocs": {
            "domains": ["evil.example", "github.com"],
            "ips": ["185.100.87.202", "140.82.112.3"],
            "hashes": ["44d88612fea8a8f36de82e1278abb02f"],
        },
    },
    "user_behavior_agent": {
        "headers": {
            "sender": "finance-team@gmail.com",
            "subject": "Payroll details update URGENT",
        },
        "body": {
             "plain": "Please review payroll changes immediately and confirm via this link.",
             "html": ""
        },
        "recipient_context": {
            "department": "finance",
            "role": "analyst",
            "historical_click_rate": 0.85,
        },
    },
}


# ---------------------------------------------------------------------------
# Application lifespan (startup / shutdown)
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize services on startup and clean up on shutdown."""
    # --- Startup ---
    setup_logging(
        log_dir=settings.log_dir,
        log_level=settings.app_log_level,
        log_format=settings.log_format,
    )
    logger.info(
        "Agentic Email Security API starting",
        environment=settings.app_env,
        host=settings.api_host,
        port=settings.api_port,
    )

    if settings.runtime_bootstrap_enabled:
        try:
            from email_security.scripts.bootstrap_runtime_state import bootstrap_runtime_state

            bootstrap_report = bootstrap_runtime_state(
                declare_results_queue=bool(settings.runtime_bootstrap_declare_results_queue),
                refresh_ioc=bool(settings.runtime_bootstrap_refresh_ioc),
                force_ioc_refresh=bool(settings.runtime_bootstrap_force_ioc_refresh),
            )
            if bootstrap_report.get("overall_ok"):
                logger.info("Runtime bootstrap complete", report=bootstrap_report)
            else:
                logger.warning("Runtime bootstrap partial failure", report=bootstrap_report)
        except Exception as exc:
            logger.warning("Runtime bootstrap failed", error=str(exc))

    stop_event = asyncio.Event()
    app.state._threat_intel_refresh_stop = stop_event
    app.state._threat_intel_refresh_task = None
    if settings.threat_intel_auto_refresh_enabled:
        # NOTE: Disabled — the threat_intel agent worker handles its own
        # background refresh.  Running a competing refresh from the API
        # server holds an exclusive SQLite write-lock on ioc_store.db for
        # minutes, blocking the agent from initializing during analyze().
        logger.info("Threat-intel auto-refresh delegated to agent worker")
    
    # Warm up large ML models to prevent cold-start latency for the first API request
    logger.info("Skipping ML model pre-warming for faster startup...")
    yield
    # --- Shutdown ---
    stop_event.set()
    task = getattr(app.state, "_threat_intel_refresh_task", None)
    if task is not None:
        task.cancel()
        try:
            await task
        except Exception:
            pass
    logger.info("Agentic Email Security API shutting down")


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Agentic Email Security System",
    description=(
        "Production-grade Agentic AI system for phishing email detection. "
        "Uses multiple independent AI agents to analyze email components "
        "and collectively determine threat levels."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

FRONTEND_DIR = Path(__file__).resolve().parent / "frontend"
app.mount("/ui-assets", StaticFiles(directory=str(FRONTEND_DIR)), name="ui-assets")


def _require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Enforce shared-key auth when enabled via configuration."""
    if not settings.api_auth_enabled:
        return

    configured = (settings.api_auth_key or "").strip()
    provided = (x_api_key or "").strip()
    if not configured:
        raise HTTPException(status_code=503, detail="API auth is enabled but API_AUTH_KEY is not configured")
    if provided != configured:
        raise HTTPException(status_code=401, detail="Invalid API key")


def _safe_filename(filename: str) -> str:
    candidate = (filename or "attachment.bin").strip()
    if not candidate:
        candidate = "attachment.bin"
    return re.sub(r"[^A-Za-z0-9._-]", "_", candidate)


def _decode_base64_content(payload: str) -> bytes:
    value = (payload or "").strip()
    if value.lower().startswith("data:") and "," in value:
        value = value.split(",", 1)[1]
    try:
        return base64.b64decode(value, validate=True)
    except binascii.Error:
        # Some clients omit base64 padding.
        padded = value + ("=" * (-len(value) % 4))
        return base64.b64decode(padded)


def _extract_urls_from_text(text: str) -> list[str]:
    if not text:
        return []
    return URL_REGEX.findall(text)


def _extract_domains(urls: list[str]) -> list[str]:
    domains = set()
    for url in urls:
        candidate = (url or "").strip()
        if not candidate:
            continue
        if "://" not in candidate:
            candidate = f"https://{candidate}"
        try:
            host = (urlparse(candidate).hostname or "").lower()
        except Exception:
            continue
        if not host:
            continue
        try:
            ipaddress.ip_address(host)
            continue
        except ValueError:
            domains.add(host)
    return sorted(domains)


def _extract_ips(content: str, urls: list[str]) -> list[str]:
    found = set(IP_REGEX.findall(content or ""))
    for url in urls:
        candidate = (url or "").strip()
        if not candidate:
            continue
        if "://" not in candidate:
            candidate = f"https://{candidate}"
        try:
            host = urlparse(candidate).hostname
            if not host:
                continue
            ipaddress.ip_address(host)
            found.add(host)
        except ValueError:
            continue
        except Exception:
            continue
    return sorted(found)


def _get_agent_test_function(agent_name: str):
    from email_security.agents.service_runner import AGENT_FUNCTIONS

    if agent_name not in AGENT_FUNCTIONS:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Unsupported agent '{agent_name}'. "
                f"Expected one of: {sorted(AGENT_FUNCTIONS)}"
            ),
        )
    return AGENT_FUNCTIONS[agent_name]


def _build_attachment_payload(
    analysis_id: str,
    attachments: list,
) -> tuple[list[dict[str, str | int]], list[str]]:
    persisted: list[dict[str, str | int]] = []
    hashes: list[str] = []

    storage_dir = Path(settings.attachment_volume_dir)

    for item in attachments:
        attachment_id = str(uuid.uuid4())
        safe_name = _safe_filename(item.filename)
        size_bytes = int(item.size_bytes or 0)
        sha256 = ""
        path = ""

        if item.content_base64:
            try:
                storage_dir.mkdir(parents=True, exist_ok=True)
                blob = _decode_base64_content(item.content_base64)
                size_bytes = len(blob)
                sha256 = hashlib.sha256(blob).hexdigest()
                target_name = f"{analysis_id}_{attachment_id}_{safe_name}"
                target_path = storage_dir / target_name
                target_path.write_bytes(blob)
                path = str(target_path)
                hashes.append(sha256)
            except Exception as exc:
                logger.warning(
                    "Attachment decode/persist failed",
                    analysis_id=analysis_id,
                    filename=item.filename,
                    error=str(exc),
                )

        persisted.append(
            {
                "attachment_id": attachment_id,
                "filename": item.filename,
                "content_type": item.content_type,
                "size_bytes": size_bytes,
                "sha256": sha256,
                "path": path,
            }
        )

    return persisted, hashes


def _soc_queue_names() -> list[str]:
    return [
        settings.results_queue,
        settings.garuda_retry_queue,
        settings.garuda_dead_letter_queue,
        "header_agent.queue",
        "content_agent.queue",
        "url_agent.queue",
        "attachment_agent.queue",
        "sandbox_agent.queue",
        "threat_intel_agent.queue",
        "user_behavior_agent.queue",
    ]


def _fetch_recent_reports(limit: int = 50) -> list[dict]:
    rows: list[dict] = []
    with psycopg2.connect(settings.database_url) as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT analysis_id, created_at, overall_risk_score, verdict, report
                FROM threat_reports
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (max(1, int(limit)),),
            )
            for analysis_id, created_at, risk_score, verdict, report in cursor.fetchall():
                if isinstance(report, dict):
                    report_dict = report
                elif isinstance(report, str):
                    try:
                        import json

                        report_dict = json.loads(report)
                    except Exception:
                        report_dict = {}
                else:
                    report_dict = {}
                rows.append(
                    {
                        "analysis_id": analysis_id,
                        "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at),
                        "overall_risk_score": float(risk_score or 0.0),
                        "verdict": verdict,
                        "recommended_actions": report_dict.get("recommended_actions", []) or [],
                        "agent_results": report_dict.get("agent_results", []) or [],
                    }
                )
    return rows


def _build_soc_overview() -> dict:
    queue_stats: list[dict] = []
    mq = RabbitMQClient()
    try:
        mq.connect()
        queue_stats = mq.get_multi_queue_stats(_soc_queue_names())
    except Exception as exc:
        queue_stats = [{"queue": "_connection", "exists": False, "error": str(exc), "messages_ready": 0, "consumers": 0}]
    finally:
        mq.close()

    reports: list[dict] = []
    reports_error = None
    try:
        reports = _fetch_recent_reports(limit=50)
    except Exception as exc:
        reports_error = str(exc)
        logger.warning("SOC overview could not fetch reports", error=reports_error)
    verdict_counts: dict[str, int] = {}
    total_risk = 0.0
    action_counts: dict[str, int] = {}
    recent_agent_outputs: list[dict] = []

    for report in reports:
        verdict = str(report.get("verdict") or "unknown")
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
        total_risk += float(report.get("overall_risk_score") or 0.0)

        for action in report.get("recommended_actions", []) or []:
            key = str(action)
            action_counts[key] = action_counts.get(key, 0) + 1

        for result in (report.get("agent_results") or [])[:10]:
            recent_agent_outputs.append(
                {
                    "analysis_id": report.get("analysis_id"),
                    "agent_name": result.get("agent_name"),
                    "risk_score": float(result.get("risk_score", 0.0) or 0.0),
                    "confidence": float(result.get("confidence", 0.0) or 0.0),
                }
            )

    avg_risk = (total_risk / len(reports)) if reports else 0.0
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "queue_health": queue_stats,
        "reports": {
            "count": len(reports),
            "avg_risk_score": round(avg_risk, 4),
            "verdict_counts": verdict_counts,
            "recent": reports[:20],
            "error": reports_error,
        },
        "response_actions": action_counts,
        "agent_outputs": recent_agent_outputs[:100],
    }


async def _threat_intel_refresh_loop(stop_event: asyncio.Event) -> None:
    """Periodically refresh IOC store and emit staleness alerts."""
    from email_security.agents.threat_intel_agent.agent import get_ioc_store_status, refresh_ioc_store

    refresh_every = max(30, int(settings.ioc_refresh_seconds))
    logger.info("Threat-intel auto-refresh loop started", refresh_every_seconds=refresh_every)
    while not stop_event.is_set():
        try:
            refresh_ioc_store(force=False)
            status = get_ioc_store_status()
            if status.get("is_stale"):
                logger.error("IOC store stale alert", status=status)
        except Exception as exc:
            logger.warning("Threat-intel auto-refresh iteration failed", error=str(exc))

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=refresh_every)
        except asyncio.TimeoutError:
            continue


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/", include_in_schema=False)
async def root_redirect():
    """Redirect root to the frontend UI."""
    return RedirectResponse(url="/ui")


@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """Return the current health status of the API service."""
    return HealthResponse(
        status="healthy",
        version="0.1.0",
        environment=settings.app_env,
    )


@app.get("/ui", tags=["Frontend"])
async def ui_home() -> FileResponse:
    """Serve SOC frontend home page."""
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/ui/analyze", tags=["Frontend"])
async def ui_analyze() -> FileResponse:
    """Serve file upload analysis page."""
    return FileResponse(FRONTEND_DIR / "analyze.html")


@app.get("/ui/agents", tags=["Frontend"])
async def ui_agents() -> FileResponse:
    """Serve individual agent testing page."""
    return FileResponse(FRONTEND_DIR / "agents.html")


@app.get("/agent-test/agents", tags=["Agent Testing"])
async def list_testable_agents(_auth: None = Depends(_require_api_key)):
    """List agents that can be tested directly with custom payloads."""
    return {
        "supported_agents": SUPPORTED_AGENT_TESTS,
        "usage": "POST /agent-test/{agent_name}",
        "note": "Direct test path bypasses RabbitMQ/orchestrator and does not alter production async flow.",
    }


@app.get("/agent-test/examples", tags=["Agent Testing"])
async def get_agent_test_examples(_auth: None = Depends(_require_api_key)):
    """Return copy-paste sample payloads for each direct agent test endpoint."""
    return {
        "usage": {
            "endpoint": "POST /agent-test/{agent_name}",
            "body": {
                "payload": "<agent-specific JSON payload>",
                "inject_analysis_id": True,
                "print_output": True,
            },
        },
        "examples": AGENT_TEST_EXAMPLES,
        "result_location": {
            "api_response": "Returned immediately in response.output",
            "stdout": "Printed in API service logs when print_output=true",
        },
    }


@app.post(
    "/agent-test/{agent_name}",
    response_model=AgentDirectTestResponse,
    tags=["Agent Testing"],
)
async def direct_agent_test(
    agent_name: str,
    request: AgentDirectTestRequest,
    _auth: None = Depends(_require_api_key),
):
    """
    Run one agent directly against caller-provided payload.

    This endpoint is isolated for manual testing and does not publish events,
    consume queues, or invoke orchestrator/action-layer workflows.
    """
    payload: dict[str, Any] = dict(request.payload or {})
    if request.inject_analysis_id and not payload.get("analysis_id"):
        payload["analysis_id"] = f"manual-agent-test-{uuid.uuid4()}"

    analyze_fn = _get_agent_test_function(agent_name)
    try:
        output = analyze_fn(payload)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Direct agent test failed", agent_name=agent_name)
        raise HTTPException(
            status_code=500,
            detail=f"Direct test for {agent_name} failed: {exc}",
        ) from exc

    if request.print_output:
        print(f"[AGENT-TEST][{agent_name}] INPUT: {payload}")
        print(f"[AGENT-TEST][{agent_name}] OUTPUT: {output}")

    logger.info(
        "Direct agent test completed",
        agent_name=agent_name,
        payload_keys=sorted(payload.keys()),
    )

    return AgentDirectTestResponse(
        status="completed",
        agent_name=agent_name,
        message=(
            "Agent tested in isolated direct mode. "
            "No RabbitMQ publish and no orchestrator/action dispatch occurred."
        ),
        input_payload=payload,
        output=output if isinstance(output, dict) else {"raw_output": output},
    )


@app.get("/soc/dashboard", tags=["SOC"], response_class=HTMLResponse)
async def soc_dashboard():
        """Simple analyst-facing SOC dashboard for queue health and outcomes."""
        return HTMLResponse(
                """
<!doctype html>
<html lang="en" class="dark">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Email Security | SOC Intelligence</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg-base: #0B0F19;
            --bg-panel: rgba(19, 26, 42, 0.7);
            --bg-card: rgba(26, 35, 58, 0.8);
            --border: rgba(65, 83, 119, 0.4);
            --text-main: #E2E8F0;
            --text-muted: #94A3B8;
            --accent-primary: #3B82F6;
            --accent-glow: rgba(59, 130, 246, 0.5);
            --red: #EF4444;
            --amber: #F59E0B;
            --green: #10B981;
            --glass-blur: blur(12px);
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: 'Inter', sans-serif;
            background: radial-gradient(circle at top right, #111827, var(--bg-base) 60%);
            color: var(--text-main);
            min-height: 100vh;
            line-height: 1.5;
            padding-bottom: 2rem;
            overflow-x: hidden;
        }

        /* Animated background elements */
        .bg-orb {
            position: fixed;
            border-radius: 50%;
            filter: blur(80px);
            z-index: -1;
            opacity: 0.4;
            animation: float 10s infinite ease-in-out alternate;
        }
        .orb-1 { top: -10%; left: -10%; width: 400px; height: 400px; background: rgba(59, 130, 246, 0.3); }
        .orb-2 { bottom: -20%; right: -10%; width: 500px; height: 500px; background: rgba(139, 92, 246, 0.2); animation-delay: -5s; }

        @keyframes float {
            0% { transform: translate(0, 0); }
            100% { transform: translate(30px, 50px); }
        }

        header {
            background: rgba(11, 15, 25, 0.8);
            backdrop-filter: var(--glass-blur);
            border-bottom: 1px solid var(--border);
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 50;
        }
        
        .logo { font-size: 1.25rem; font-weight: 700; display: flex; align-items: center; gap: 0.5rem; }
        .logo span { color: var(--accent-primary); }
        .timestamp { font-family: monospace; font-size: 0.875rem; color: var(--text-muted); background: var(--bg-card); padding: 0.25rem 0.75rem; border-radius: 9999px; border: 1px solid var(--border); }

        .container { max-width: 1400px; margin: 2rem auto; padding: 0 1.5rem; display: grid; gap: 1.5rem; }
        
        /* Glass Panels */
        .panel {
            background: var(--bg-panel);
            backdrop-filter: var(--glass-blur);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 1.5rem;
            box-shadow: 0 4px 20px rgba(0,0,0,0.2);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        .panel:hover { box-shadow: 0 8px 30px rgba(0,0,0,0.3); }
        .panel-title { font-size: 1rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 1.25rem; display: flex; justify-content: space-between; align-items: center; }

        /* KPI Grid */
        .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; }
        .kpi-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 1.25rem; text-align: center; position: relative; overflow: hidden; }
        .kpi-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; background: var(--accent-primary); opacity: 0.5; }
        .kpi-value { font-size: 2.5rem; font-weight: 700; margin: 0.5rem 0; line-height: 1; }
        .kpi-label { font-size: 0.875rem; color: var(--text-muted); }
        
        .val-red { color: var(--red); }
        .val-amber { color: var(--amber); }
        .val-green { color: var(--green); }
        .val-blue { color: var(--accent-primary); }

        /* Charts Layout */
        .chart-row { display: grid; grid-template-columns: 1fr 2fr; gap: 1.5rem; }
        .chart-container { position: relative; height: 300px; width: 100%; }

        /* Tables */
        .table-wrap { overflow-x: auto; border-radius: 8px; border: 1px solid var(--border); }
        table { width: 100%; border-collapse: collapse; font-size: 0.875rem; white-space: nowrap; }
        th { background: rgba(0,0,0,0.2); padding: 1rem; text-align: left; font-weight: 600; color: var(--text-muted); border-bottom: 1px solid var(--border); }
        td { padding: 1rem; border-bottom: 1px solid rgba(65, 83, 119, 0.2); }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: rgba(255,255,255,0.03); }
        
        .pill { padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; display: inline-flex; align-items: center; gap: 0.25rem; }
        .pill.malicious { background: rgba(239, 68, 68, 0.2); color: #FCA5A5; border: 1px solid rgba(239, 68, 68, 0.3); }
        .pill.high_risk { background: rgba(245, 158, 11, 0.2); color: #FCD34D; border: 1px solid rgba(245, 158, 11, 0.3); }
        .pill.suspicious { background: rgba(245, 158, 11, 0.1); color: #FDE68A; border: 1px solid rgba(245, 158, 11, 0.2); }
        .pill.safe, .pill.likely_safe { background: rgba(16, 185, 129, 0.2); color: #6EE7B7; border: 1px solid rgba(16, 185, 129, 0.3); }
        .pill.action { background: rgba(59, 130, 246, 0.2); color: #93C5FD; border: 1px solid rgba(59, 130, 246, 0.3); margin-right: 0.25rem; }

        .hash-id { font-family: monospace; color: var(--text-muted); }
        
        /* Animations */
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        .fade-in { animation: fadeIn 0.5s ease forwards; }
        .d-1 { animation-delay: 0.1s; } .d-2 { animation-delay: 0.2s; } .d-3 { animation-delay: 0.3s; }
        
        @media (max-width: 900px) {
            .chart-row { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="bg-orb orb-1"></div>
    <div class="bg-orb orb-2"></div>

    <header>
        <div class="logo">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="color:var(--accent-primary)"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
            SOC <span>Intelligence</span>
        </div>
        <div id="ts" class="timestamp">Connecting...</div>
    </header>

    <div class="container">
        <!-- Key Metrics -->
        <div class="kpi-grid fade-in">
            <div class="kpi-card">
                <div class="kpi-label">Analyzed Emails</div>
                <div class="kpi-value val-blue" id="kpi-total">-</div>
            </div>
            <div class="kpi-card" style="--accent-primary: var(--red);">
                <div class="kpi-label">Malicious Threats</div>
                <div class="kpi-value val-red" id="kpi-malicious">-</div>
            </div>
            <div class="kpi-card" style="--accent-primary: var(--amber);">
                <div class="kpi-label">Average Risk Score</div>
                <div class="kpi-value val-amber" id="kpi-risk">-</div>
            </div>
            <div class="kpi-card" style="--accent-primary: var(--green);">
                <div class="kpi-label">Active Agents/Queues</div>
                <div class="kpi-value val-green" id="kpi-queues">-</div>
            </div>
        </div>

        <!-- Charts -->
        <div class="chart-row fade-in d-1">
            <div class="panel">
                <div class="panel-title">Verdict Distribution</div>
                <div class="chart-container">
                    <canvas id="verdictChart"></canvas>
                </div>
            </div>
            <div class="panel">
                <div class="panel-title">Automated Response Actions</div>
                <div class="chart-container">
                    <canvas id="actionChart"></canvas>
                </div>
            </div>
        </div>

        <!-- Recent Threats Table -->
        <div class="panel fade-in d-2">
            <div class="panel-title">
                Recent Threat Reports
                <span class="pill" style="background: rgba(255,255,255,0.1); border:none; color:white;" id="report-count">0 items</span>
            </div>
            <div class="table-wrap">
                <table id="reports-table">
                    <thead>
                        <tr>
                            <th>Analysis ID</th>
                            <th>Time</th>
                            <th>Verdict</th>
                            <th>Risk Score</th>
                            <th>Remediation Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr><td colspan="5" style="text-align:center; color:var(--text-muted);">Initializing telemetry...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        // Chart instances
        let verdictChart = null;
        let actionChart = null;

        // Chart.js global defaults for dark theme
        Chart.defaults.color = '#94A3B8';
        Chart.defaults.borderColor = 'rgba(65, 83, 119, 0.2)';
        Chart.defaults.font.family = "'Inter', sans-serif";

        function initCharts() {
            const ctx1 = document.getElementById('verdictChart').getContext('2d');
            verdictChart = new Chart(ctx1, {
                type: 'doughnut',
                data: {
                    labels: ['Malicious', 'High Risk', 'Suspicious', 'Safe'],
                    datasets: [{
                        data: [0, 0, 0, 0],
                        backgroundColor: ['#EF4444', '#F59E0B', '#FCD34D', '#10B981'],
                        borderWidth: 0,
                        hoverOffset: 4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '75%',
                    plugins: {
                        legend: { position: 'bottom', labels: { padding: 20, usePointStyle: true, pointStyle: 'circle' } }
                    }
                }
            });

            const ctx2 = document.getElementById('actionChart').getContext('2d');
            
            // Create gradient for bars
            const gradient = ctx2.createLinearGradient(0, 0, 0, 400);
            gradient.addColorStop(0, 'rgba(59, 130, 246, 0.8)');
            gradient.addColorStop(1, 'rgba(59, 130, 246, 0.2)');

            actionChart = new Chart(ctx2, {
                type: 'bar',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Executions',
                        data: [],
                        backgroundColor: gradient,
                        borderRadius: 6,
                        borderWidth: 1,
                        borderColor: 'rgba(59, 130, 246, 1)'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: { beginAtZero: true, grid: { drawBorder: false } },
                        x: { grid: { display: false } }
                    },
                    plugins: {
                        legend: { display: false }
                    }
                }
            });
        }

        function formatVerdict(v) {
            const normalized = String(v).toLowerCase();
            return `<span class="pill ${normalized}">${String(v).toUpperCase().replace('_', ' ')}</span>`;
        }

        function formatActions(actions) {
            if (!actions || actions.length === 0) return `<span class="pill" style="background:transparent;border:1px dashed var(--border);color:var(--text-muted)">None</span>`;
            return actions.map(a => `<span class="pill action">${a}</span>`).join('');
        }

        async function refreshData() {
            try {
                const res = await fetch('/soc/overview');
                const data = await res.json();
                
                // Update Timestamp
                document.getElementById('ts').innerHTML = `Live &bull; ${new Date(data.generated_at).toLocaleTimeString()}`;

                // Update KPIs
                const reports = data.reports || {};
                const verdicts = reports.verdict_counts || {};
                const queues = (data.queue_health || []).filter(q => q.exists).length;
                
                document.getElementById('kpi-total').textContent = reports.count || 0;
                document.getElementById('kpi-malicious').textContent = verdicts.malicious || 0;
                document.getElementById('kpi-risk').textContent = (reports.avg_risk_score || 0).toFixed(2);
                document.getElementById('kpi-queues').textContent = queues;

                // Update Verdict Chart
                if (verdictChart) {
                    verdictChart.data.datasets[0].data = [
                        verdicts.malicious || 0,
                        verdicts.high_risk || 0,
                        verdicts.suspicious || 0,
                        (verdicts.safe || 0) + (verdicts.likely_safe || 0)
                    ];
                    verdictChart.update();
                }

                // Update Action Chart
                if (actionChart && data.response_actions) {
                    const actionEntries = Object.entries(data.response_actions).sort((a,b) => b[1] - a[1]);
                    actionChart.data.labels = actionEntries.map(e => e[0].replace(/_/g, ' '));
                    actionChart.data.datasets[0].data = actionEntries.map(e => e[1]);
                    actionChart.update();
                }

                // Update Table
                const tbody = document.querySelector('#reports-table tbody');
                document.getElementById('report-count').textContent = `${(reports.recent || []).length} items`;
                
                if (reports.recent && reports.recent.length > 0) {
                    tbody.innerHTML = reports.recent.map(r => `
                        <tr>
                            <td class="hash-id">${r.analysis_id.substring(0,8)}...${r.analysis_id.substring(r.analysis_id.length-4)}</td>
                            <td style="color:var(--text-muted)">${new Date(r.created_at).toLocaleTimeString()}</td>
                            <td>${formatVerdict(r.verdict)}</td>
                            <td>
                                <div style="display:flex; align-items:center; gap:8px;">
                                    <div style="width:50px; height:6px; background:var(--bg-base); border-radius:3px; overflow:hidden;">
                                        <div style="width:${Math.min(100, r.overall_risk_score * 100)}%; height:100%; background: ${r.overall_risk_score > 0.8 ? 'var(--red)' : r.overall_risk_score > 0.5 ? 'var(--amber)' : 'var(--green)'};"></div>
                                    </div>
                                    <span style="font-family:monospace">${r.overall_risk_score.toFixed(2)}</span>
                                </div>
                            </td>
                            <td>${formatActions(r.recommended_actions)}</td>
                        </tr>
                    `).join('');
                } else {
                    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--text-muted); padding: 2rem;">No recent activity</td></tr>`;
                }

            } catch (err) {
                console.error("Dashboard refresh failed:", err);
                document.getElementById('ts').innerHTML = `<span style="color:var(--red)">Connection Lost</span>`;
            }
        }

        // Initialize
        document.addEventListener('DOMContentLoaded', () => {
            initCharts();
            refreshData();
            setInterval(refreshData, 5000); // 5s refresh
        });
    </script>
</body>
</html>
                """
        )


@app.get("/soc/overview", tags=["SOC"])
async def soc_overview(_auth: None = Depends(_require_api_key)):
        """Dashboard backing API for queue health, verdicts, and response actions."""
        return _build_soc_overview()


@app.websocket("/ws/orchestrator")
async def orchestrator_ws(websocket: WebSocket):
    """Real-time pipeline progress via WebSocket. Clients receive agent_update
    and final_verdict events as they happen."""
    await websocket.accept()
    redis_sub = None
    try:
        redis_sub = redis_async.from_url(settings.redis_url)
        pubsub = redis_sub.pubsub()
        await pubsub.subscribe("pipeline_ui_events")
        while True:
            msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if msg and msg["type"] == "message":
                await websocket.send_text(msg["data"].decode() if isinstance(msg["data"], bytes) else msg["data"])
            await asyncio.sleep(0.05)
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.warning(f"WebSocket error: {exc}")
    finally:
        if redis_sub:
            await redis_sub.aclose()


@app.post("/ops/garuda/process-retries", tags=["Operations"])
async def process_garuda_retry_queue(max_items: int = 25, _auth: None = Depends(_require_api_key)):
        """Process pending Garuda retries and return reconciliation stats."""
        from email_security.garuda_integration.retry_queue import process_garuda_retries

        return process_garuda_retries(max_items=max_items)


@app.get("/ops/threat-intel/status", tags=["Operations"])
async def threat_intel_status(_auth: None = Depends(_require_api_key)):
        """Return IOC store lifecycle health and staleness information."""
        from email_security.agents.threat_intel_agent.agent import get_ioc_store_status

        return get_ioc_store_status()


@app.post("/ops/threat-intel/refresh", tags=["Operations"])
async def threat_intel_refresh(force: bool = False, _auth: None = Depends(_require_api_key)):
        """Trigger IOC feed refresh lifecycle job now."""
        from email_security.agents.threat_intel_agent.agent import refresh_ioc_store

        return refresh_ioc_store(force=force)


@app.post(
    "/analyze-email",
    response_model=EmailAnalysisResponse,
    tags=["Analysis"],
)
async def analyze_email(request: EmailAnalysisRequest, _auth: None = Depends(_require_api_key)):
    """
    Accept an email for phishing analysis.

    This endpoint normalizes payload content, persists attachments, extracts
    IOC candidates, and publishes a NewEmailEvent for downstream agents.
    Final reports are retrieved asynchronously via GET /reports/{analysis_id}.
    """
    analysis_id = str(uuid.uuid4())
    body_plain = request.body or ""

    request_urls = [url.strip() for url in request.urls if str(url).strip()]
    discovered_urls = _extract_urls_from_text(body_plain)
    all_urls = sorted(set(request_urls + discovered_urls))

    attachments, attachment_hashes = _build_attachment_payload(
        analysis_id=analysis_id,
        attachments=request.attachments,
    )

    # OCR: extract hidden URLs from image/PDF attachments
    ocr_urls: list[str] = []
    try:
        from email_security.services.ocr_service import extract_urls_from_attachments
        ocr_urls = extract_urls_from_attachments(attachments)
        if ocr_urls:
            all_urls = sorted(set(all_urls + ocr_urls))
    except Exception:
        pass

    ioc_domains = _extract_domains(all_urls)
    ioc_ips = _extract_ips(
        content=f"{request.headers.subject}\n{body_plain}",
        urls=all_urls,
    )

    payload = {
        "event_type": "NewEmailEvent",
        "analysis_id": analysis_id,
        "ingested_at": datetime.now(timezone.utc).isoformat(),
        "headers": {
            "sender": request.headers.sender,
            "reply_to": request.headers.reply_to,
            "subject": request.headers.subject,
            "received": request.headers.received,
            "message_id": request.headers.message_id,
            "authentication_results": request.headers.authentication_results,
            "to": request.headers.to,
            "raw": {},
        },
        "body": {
            "plain": body_plain,
            "html": "",
        },
        "urls": all_urls,
        "attachments": attachments,
        "iocs": {
            "domains": ioc_domains,
            "ips": ioc_ips,
            "hashes": attachment_hashes,
        },
    }

    from email_security.orchestrator.deduplication import dedup_email_analysis
    dedup_result, was_cached, fingerprint = dedup_email_analysis(payload)
    
    if was_cached and dedup_result:
        cached_analysis_id = dedup_result.get("analysis_id", analysis_id)
        logger.info(
            "Email deduplicated from cache",
            analysis_id=analysis_id,
            cached_analysis_id=cached_analysis_id,
            fingerprint=fingerprint,
        )
        return EmailAnalysisResponse(
            status="cached",
            message="Identical email analysis found in cache. Processing skipped.",
            analysis_id=cached_analysis_id,
            agent_results=dedup_result.get("agent_results", []),
            overall_risk_score=dedup_result.get("overall_risk_score"),
            verdict=dedup_result.get("verdict"),
            llm_explanation=dedup_result.get("llm_explanation"),
            report_endpoint=f"/reports/{cached_analysis_id}",
            final_report_features=[
                "agent_results",
                "overall_risk_score",
                "verdict",
                "llm_explanation",
                "counterfactual_result",
                "threat_storyline",
                "recommended_actions",
            ],
        )

    # Cache the mapping so runner.py can cache the final result using this fingerprint
    if fingerprint and settings.request_deduplication_enabled:
        try:
            import redis
            r = redis.from_url(settings.redis_url or "redis://localhost:6379/0")
            r.setex(f"email_dedup_mapping:{analysis_id}", settings.orchestrator_cache_ttl_seconds, fingerprint)
        except Exception as e:
            logger.warning("Failed to store deduplication mapping", error=str(e))

    mq_client = RabbitMQClient()
    mq_client.connect()
    mq_client.publish_new_email(payload)
    mq_client.close()

    logger.info(
        "Email received for analysis",
        analysis_id=analysis_id,
        sender=request.headers.sender,
        subject=request.headers.subject,
        url_count=len(all_urls),
        attachment_count=len(attachments),
        ioc_domain_count=len(ioc_domains),
        ioc_ip_count=len(ioc_ips),
        attachment_hash_count=len(attachment_hashes),
    )

    return EmailAnalysisResponse(
        status="received",
        message="Email event accepted and dispatched to all agents",
        analysis_id=analysis_id,
        agent_results=[],
        overall_risk_score=None,
        verdict=None,
        llm_explanation=None,
        report_endpoint=f"/reports/{analysis_id}",
        final_report_features=[
            "agent_results",
            "overall_risk_score",
            "verdict",
            "llm_explanation",
            "counterfactual_result",
            "threat_storyline",
            "recommended_actions",
        ],
    )


@app.post("/ingest-raw-email", response_model=EmailAnalysisResponse, tags=["Analysis"])
async def ingest_raw_email(file: UploadFile = File(...), _auth: None = Depends(_require_api_key)):
    """Accept raw .eml/.txt file, parse it fully, and publish NewEmailEvent."""
    suffix = Path(file.filename or "email.eml").suffix.lower()
    parser = EmailParserService()
    if not parser.supports_extension(suffix):
        supported = ", ".join(sorted(parser.supported_extensions()))
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file extension '{suffix}'. Supported: {supported}",
        )

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
        temp_file.write(await file.read())
        temp_path = temp_file.name

    try:
        event = parser.parse_and_publish(temp_path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to parse raw email: {exc}") from exc

    return EmailAnalysisResponse(
        status="received",
        message="Raw email parsed and dispatched",
        analysis_id=event["analysis_id"],
        agent_results=[],
        overall_risk_score=None,
        verdict=None,
        llm_explanation=None,
        report_endpoint=f"/reports/{event['analysis_id']}",
        final_report_features=[
            "agent_results",
            "overall_risk_score",
            "verdict",
            "llm_explanation",
            "counterfactual_result",
            "threat_storyline",
            "recommended_actions",
        ],
    )


@app.get("/reports/{analysis_id}", tags=["Analysis"])
async def get_report(analysis_id: str, _auth: None = Depends(_require_api_key)):
    """Return final orchestrator report for an analysis id."""
    try:
        with psycopg2.connect(settings.database_url) as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT report
                    FROM threat_reports
                    WHERE analysis_id = %s
                    """,
                    (analysis_id,),
                )
                row = cursor.fetchone()
                if not row:
                    raise HTTPException(status_code=404, detail="Report not ready")
                return row[0]
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch report: {exc}") from exc

@app.get("/api/v1/pewpew")
async def pew_pew():
    """Easter Egg: Pew Pew!"""
    return {
        "status": "pew pew",
        "message": "Lasers fired at incoming phishing emails! 💥🔫👾",
        "ascii_art": r"""
        \ \ / /
         \ V / 
         | |  
         |_|  
        """
    }
