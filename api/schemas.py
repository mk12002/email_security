"""
Pydantic schemas for the Email Analysis API.

Defines request and response models for all API endpoints.
"""

from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Agent result schema (shared by all agents)
# ---------------------------------------------------------------------------

class AgentResult(BaseModel):
    """Standard output schema returned by every analysis agent."""

    agent_name: str = Field(..., description="Name of the analysis agent")
    risk_score: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Risk score between 0 and 1"
    )
    confidence: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Confidence level between 0 and 1"
    )
    indicators: list[str] = Field(
        default_factory=list, description="List of detected threat indicators"
    )


# ---------------------------------------------------------------------------
# Email analysis request
# ---------------------------------------------------------------------------

class EmailHeaders(BaseModel):
    """Parsed email header fields."""

    sender: str = Field(..., description="Sender email address")
    reply_to: Optional[str] = Field(default=None, description="Reply-To address")
    subject: str = Field(default="", description="Email subject line")
    received: list[str] = Field(
        default_factory=list, description="Received header chain"
    )
    message_id: Optional[str] = Field(default=None, description="Message-ID header")
    authentication_results: Optional[str] = Field(
        default=None, description="SPF/DKIM/DMARC results"
    )


class AttachmentInfo(BaseModel):
    """Metadata for an email attachment."""

    filename: str = Field(..., description="Attachment filename")
    content_type: str = Field(..., description="MIME content type")
    size_bytes: int = Field(default=0, description="File size in bytes")
    content_base64: Optional[str] = Field(
        default=None, description="Base64-encoded file content"
    )


class EmailAnalysisRequest(BaseModel):
    """Request body for the /analyze-email endpoint."""

    headers: EmailHeaders
    body: str = Field(default="", description="Plain-text or HTML email body")
    urls: list[str] = Field(
        default_factory=list, description="URLs extracted from the email"
    )
    attachments: list[AttachmentInfo] = Field(
        default_factory=list, description="Email attachments"
    )


# ---------------------------------------------------------------------------
# Email analysis response
# ---------------------------------------------------------------------------

class EmailAnalysisResponse(BaseModel):
    """Response body for the /analyze-email endpoint."""

    status: str = Field(..., description="Processing status")
    message: str = Field(..., description="Human-readable result message")
    analysis_id: Optional[str] = Field(
        default=None, description="Unique analysis tracking ID"
    )
    agent_results: list[AgentResult] = Field(
        default_factory=list, description="Individual agent analysis results"
    )
    overall_risk_score: Optional[float] = Field(
        default=None, description="Aggregated risk score"
    )
    verdict: Optional[str] = Field(default=None, description="Final decision verdict")
    llm_explanation: Optional[str] = Field(
        default=None, description="LLM-generated explanation for SOC analysts"
    )


class HealthResponse(BaseModel):
    """Response body for the /health endpoint."""

    status: str = Field(default="healthy")
    version: str = Field(default="0.1.0")
    environment: str = Field(default="development")
