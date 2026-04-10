# =============================================================================
# Agentic Email Security System – Dockerfile
# =============================================================================
# Multi-stage build for production API service
# =============================================================================

# --- Stage 1: Builder ---
FROM python:3.11-slim AS builder

WORKDIR /build

# Install system dependencies for security libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libfuzzy-dev \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# --- Stage 2: Runtime ---
FROM python:3.11-slim AS runtime

LABEL maintainer="Email Security Team"
LABEL description="Agentic AI Phishing Email Detection System"
LABEL version="0.1.0"

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libfuzzy2 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1001 appuser \
    && useradd --uid 1001 --gid appuser --shell /bin/bash --create-home appuser

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

WORKDIR /app

# Copy application code
COPY . /app/email_security

ENV PYTHONPATH=/app

# Create required directories
RUN mkdir -p /app/email_security/logs /app/email_security/models /app/email_security/datasets /app/email_security/datasets_processed /app/email_security/threat_intelligence /app/models \
    && chown -R appuser:appuser /app

USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

CMD ["uvicorn", "email_security.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
