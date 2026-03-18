"""
Base FastAPI application for the Agentic Email Security System.

Exposes health check and email analysis endpoints.
This service will be extended in later phases with full agent orchestration.
"""

import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
import tempfile

from fastapi import FastAPI
from fastapi import File, HTTPException, UploadFile
from loguru import logger
import psycopg2

from api.schemas import (
    EmailAnalysisRequest,
    EmailAnalysisResponse,
    HealthResponse,
)
from configs.settings import settings
from services.email_parser import EmailParserService
from services.logging_service import setup_logging
from services.messaging_service import RabbitMQClient


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

    In later phases this endpoint will dispatch email data to all analysis
    agents in parallel and return aggregated threat scores.

    Currently returns an acknowledgement placeholder.
    """
    analysis_id = str(uuid.uuid4())

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
            "plain": request.body,
            "html": "",
        },
        "urls": request.urls,
        "attachments": [
            {
                "attachment_id": str(uuid.uuid4()),
                "filename": item.filename,
                "content_type": item.content_type,
                "size_bytes": item.size_bytes,
                "sha256": "",
                "path": "",
            }
            for item in request.attachments
        ],
        "iocs": {
            "domains": [],
            "ips": [],
            "hashes": [],
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
        url_count=len(request.urls),
        attachment_count=len(request.attachments),
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
