"""
Base FastAPI application for the Agentic Email Security System.

Exposes health check and email analysis endpoints.
This service will be extended in later phases with full agent orchestration.
"""

import base64
import binascii
import hashlib
import ipaddress
import re
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
import tempfile
from urllib.parse import urlparse

from fastapi import FastAPI
from fastapi import File, HTTPException, UploadFile
from loguru import logger
import psycopg2

from email_security.api.schemas import (
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
    yield
    # --- Shutdown ---
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


def _build_attachment_payload(
    analysis_id: str,
    attachments: list,
) -> tuple[list[dict[str, str | int]], list[str]]:
    persisted: list[dict[str, str | int]] = []
    hashes: list[str] = []

    storage_dir = Path(settings.attachment_volume_dir)
    storage_dir.mkdir(parents=True, exist_ok=True)

    for item in attachments:
        attachment_id = str(uuid.uuid4())
        safe_name = _safe_filename(item.filename)
        size_bytes = int(item.size_bytes or 0)
        sha256 = ""
        path = ""

        if item.content_base64:
            try:
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


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """Return the current health status of the API service."""
    return HealthResponse(
        status="healthy",
        version="0.1.0",
        environment=settings.app_env,
    )


@app.post(
    "/analyze-email",
    response_model=EmailAnalysisResponse,
    tags=["Analysis"],
)
async def analyze_email(request: EmailAnalysisRequest):
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
            "to": [],
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
    )


@app.post("/ingest-raw-email", response_model=EmailAnalysisResponse, tags=["Analysis"])
async def ingest_raw_email(file: UploadFile = File(...)):
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
    )


@app.get("/reports/{analysis_id}", tags=["Analysis"])
async def get_report(analysis_id: str):
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
