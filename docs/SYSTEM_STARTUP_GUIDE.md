# Agentic Email Security System — Complete Startup & Run Guide

> **Last Updated:** April 20, 2026

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Architecture Overview](#architecture-overview)
3. [Step 1 — Environment Configuration](#step-1--environment-configuration)
4. [Step 2 — Start Infrastructure (Docker)](#step-2--start-infrastructure-docker)
5. [Step 3 — Start the API Server](#step-3--start-the-api-server)
6. [Step 4 — Start Agent Workers](#step-4--start-agent-workers)
7. [Step 5 — Start the Orchestrator](#step-5--start-the-orchestrator)
8. [Step 6 — (Optional) Start the Parser Worker](#step-6--optional-start-the-parser-worker)
9. [Accessing the Frontend](#accessing-the-frontend)
10. [Testing with .eml Files](#testing-with-eml-files)
11. [Full Docker Deployment (Alternative)](#full-docker-deployment-alternative)
12. [API Endpoints Reference](#api-endpoints-reference)
13. [Troubleshooting](#troubleshooting)
14. [Shutdown Procedure](#shutdown-procedure)

---

## Prerequisites

| Requirement | Minimum Version | Notes |
|---|---|---|
| Python | 3.10+ | 3.11 recommended |
| Docker | 29.x | For infrastructure containers |
| Docker Compose | v5.x (plugin) | `docker compose` (not `docker-compose`) |
| OS | Linux | Tested on Ubuntu / Kali Linux |
| RAM | 8 GB+ | ML models need ~2 GB during warm-up |

### API Keys Required (configured in `.env`)

| Service | Variable | Required? |
|---|---|---|
| Azure OpenAI | `AZURE_OPENAI_API_KEY` | **Yes** — LLM reasoning / explanations |
| VirusTotal | `VIRUSTOTAL_API_KEY` | Recommended — URL & hash lookups |
| Google Safe Browsing | `GOOGLE_SAFE_BROWSING_API_KEY` | Recommended |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | Recommended |
| URLScan | `URLSCAN_API_KEY` | Optional |
| Shodan | `SHODAN_API_KEY` | Optional |
| OCR.space | `OCR_SPACE_API_KEY` | Optional — image/PDF text extraction |

---

## Architecture Overview

The system has **4 process groups** that must all be running:

```
┌──────────────────────────────────────────────────────┐
│  INFRASTRUCTURE (Docker containers)                  │
│  PostgreSQL · Redis · RabbitMQ                       │
└───────────────────────┬──────────────────────────────┘
                        │
┌───────────────────────▼──────────────────────────────┐
│  API SERVER (FastAPI + Uvicorn)                       │
│  Serves frontend UI · Accepts /analyze-email          │
│  Accepts /ingest-raw-email · Serves /reports/{id}     │
└───────────────────────┬──────────────────────────────┘
                        │ publishes events to RabbitMQ
┌───────────────────────▼──────────────────────────────┐
│  7 AGENT WORKERS (one process per agent)              │
│  header · content · url · attachment · sandbox        │
│  threat_intel · user_behavior                         │
│  Each consumes from its own RabbitMQ queue             │
│  Each publishes results to email.results.queue         │
└───────────────────────┬──────────────────────────────┘
                        │
┌───────────────────────▼──────────────────────────────┐
│  ORCHESTRATOR                                         │
│  Consumes email.results.queue                         │
│  Merges results · Runs LangGraph pipeline             │
│  Generates verdict, scores, LLM explanation            │
│  Saves report to PostgreSQL                            │
└──────────────────────────────────────────────────────┘
```

---

## Step 1 — Environment Configuration

```bash
cd /home/LabsKraft/new_work/email_security
```

The `.env` file is already configured. Key local-dev overrides at the bottom of `.env` connect to Docker-hosted infrastructure:

```ini
# LOCAL DEVELOPMENT OVERRIDES (already set in .env)
RABBITMQ_HOST=localhost
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/email_security
REDIS_URL=redis://localhost:6379/0
IOC_DB_PATH=data/ioc_store.db
EMAIL_DROP_DIR=./email_drop
ATTACHMENT_VOLUME_DIR=./attachments
```

> **Tip:** If running everything inside Docker instead, comment out these overrides.

---

## Step 2 — Start Infrastructure (Docker)

Start **only** the infrastructure containers (PostgreSQL, Redis, RabbitMQ):

```bash
cd /home/LabsKraft/new_work/email_security/docker

# Start infrastructure services only
docker compose up -d database redis rabbitmq
```

**Verify all 3 are healthy:**

```bash
docker ps --format "table {{.Names}}\t{{.Status}}"
```

Expected output:

```
NAMES                     STATUS
email-security-db         Up X minutes (healthy)
email-security-rabbitmq   Up X minutes (healthy)
email-security-redis      Up X minutes (healthy)
```

Wait until all show `(healthy)` before proceeding (can take 30–60 seconds on first boot).

### Quick Health Checks

```bash
# PostgreSQL
docker exec email-security-db pg_isready -U postgres

# Redis
docker exec email-security-redis redis-cli ping

# RabbitMQ (management UI available at http://localhost:15672, guest/guest)
docker exec email-security-rabbitmq rabbitmq-diagnostics -q ping
```

---

## Step 3 — Start the API Server

Open **Terminal 1**:

```bash
cd /home/LabsKraft/new_work
source venv/bin/activate
export PYTHONPATH=/home/LabsKraft/new_work

uvicorn email_security.api.main:app --host 0.0.0.0 --port 8000
```

**What happens during startup:**

1. Logging system initializes
2. RabbitMQ connection test (declares exchanges/queues)
3. Runtime bootstrap (IOC store refresh, results queue declaration)
4. **ML model warm-up** — loads the content phishing detection transformer model (~60–120 seconds on first run)
5. Threat-intel auto-refresh loop starts

**Wait for this line:**

```
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

**Verify:**

```bash
curl http://localhost:8000/health
# {"status":"healthy","version":"0.1.0","environment":"development"}
```

---

## Step 4 — Start Agent Workers

Open **Terminal 2**. Each of the 7 agents runs as a separate background process:

```bash
cd /home/LabsKraft/new_work
source venv/bin/activate
export PYTHONPATH=/home/LabsKraft/new_work

# Start all 7 agents as background processes
for agent in header_agent content_agent url_agent attachment_agent sandbox_agent threat_intel_agent user_behavior_agent; do
    AGENT_NAME=$agent nohup python -m email_security.agents.service_runner \
        > /tmp/${agent}.log 2>&1 &
    echo "Started $agent (PID=$!)"
done
```

**Verify all 7 are running:**

```bash
ps aux | grep service_runner | grep -v grep | wc -l
# Should output: 7
```

**Check individual agent logs:**

```bash
tail -20 /tmp/header_agent.log
tail -20 /tmp/content_agent.log
# etc.
```

> **Note:** Each agent connects to RabbitMQ, declares its own queue (`header_agent.queue`, etc.), and begins consuming messages.

---

## Step 5 — Start the Orchestrator

Open **Terminal 3**:

```bash
cd /home/LabsKraft/new_work
source venv/bin/activate
export PYTHONPATH=/home/LabsKraft/new_work

python -m email_security.orchestrator.runner
```

**Expected output:**

```
Logging system initialized
RabbitMQ connected
Consuming queue
```

The orchestrator:
- Creates the `threat_reports` table in PostgreSQL (if it doesn't exist)
- Declares and consumes from `email.results.queue`
- Waits for all 7 agent results per `analysis_id`, then runs the LangGraph pipeline
- Saves the final report to PostgreSQL

---

## Step 6 — (Optional) Start the Parser Worker

If you want the system to **automatically parse .eml files dropped** into the `email_drop/` directory:

Open **Terminal 4**:

```bash
cd /home/LabsKraft/new_work
source venv/bin/activate
export PYTHONPATH=/home/LabsKraft/new_work

python -m email_security.services.parser_worker
```

This polls `./email_drop/` every 2 seconds, parses any new `.eml` files, and publishes `NewEmailEvent` to RabbitMQ — triggering the full pipeline automatically.

---

## Accessing the Frontend

Once the API server is running:

| Page | URL | Description |
|---|---|---|
| **SOC Dashboard** | http://localhost:8000/ui | Main dashboard — queue health, verdict history, agent outputs |
| **Email Analysis** | http://localhost:8000/ui/analyze | Upload `.eml`/`.msg`/`.txt` files for full pipeline analysis |
| **Agent Testing** | http://localhost:8000/ui/agents | Test individual agents with custom payloads |
| **SOC Live Dashboard** | http://localhost:8000/soc/dashboard | Analyst-facing dashboard with auto-refresh |
| **API Docs** | http://localhost:8000/docs | Swagger/OpenAPI interactive docs |
| **RabbitMQ Management** | http://localhost:15672 | Queue monitoring (login: `guest` / `guest`) |

---

## Testing with .eml Files

### Method 1: Frontend Upload (Recommended)

1. Navigate to **http://localhost:8000/ui/analyze**
2. Drag and drop (or click to browse) an `.eml` file
3. Click **🚀 Start Analysis**
4. Watch the **Live Agent Pipeline** for real-time WebSocket updates
5. The report auto-loads when all 7 agents finish

### Method 2: cURL Upload

```bash
curl -X POST http://localhost:8000/ingest-raw-email \
  -F "file=@./email_drop/live_check_sample.eml"
```

Response gives you an `analysis_id`. Poll the report:

```bash
curl http://localhost:8000/reports/<analysis_id>
```

### Method 3: Parser Worker (File Drop)

Copy `.eml` files into `./email_drop/` and the parser worker auto-detects and processes them.

### Available Test Files

| File | Type | Description |
|---|---|---|
| `email_drop/live_check_sample.eml` | **Malicious** | Fake invoice, double-extension `.pdf.exe` attachment, Win32 API shellcode payload |
| `email_drop/IEEE ICNPCV 2026 - PAYMENT REMINDER.eml` | **Legitimate** | Real IEEE conference payment reminder via Microsoft CMT, DKIM/SPF/DMARC all pass |
| `email_drop/Dabur & Sony invite you to AINCAT'26.eml` | **Legitimate** | Conference invitation email |

---

## Full Docker Deployment (Alternative)

To run **everything** inside Docker (no local Python needed):

```bash
cd /home/LabsKraft/new_work/email_security/docker

# Build and start all services
docker compose up --build -d

# With sandbox detonation support (dev only)
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build -d
```

This starts all containers: `api_service`, `parser_service`, `orchestrator_service`, all 7 agent services, `database`, `redis`, `rabbitmq`.

**View logs:**

```bash
docker compose logs -f api_service
docker compose logs -f orchestrator_service
docker compose logs -f header_agent_service
```

---

## API Endpoints Reference

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `GET` | `/ui` | SOC Dashboard |
| `GET` | `/ui/analyze` | File upload analysis page |
| `GET` | `/ui/agents` | Individual agent testing |
| `POST` | `/analyze-email` | Submit structured email JSON for analysis |
| `POST` | `/ingest-raw-email` | Upload raw `.eml`/`.msg`/`.txt` file |
| `GET` | `/reports/{analysis_id}` | Fetch completed analysis report |
| `GET` | `/soc/dashboard` | Live SOC dashboard |
| `GET` | `/soc/overview` | SOC data API (queue health, verdicts) |
| `GET` | `/agent-test/agents` | List testable agents |
| `GET` | `/agent-test/examples` | Sample payloads for each agent |
| `POST` | `/agent-test/{agent_name}` | Direct single-agent test |
| `GET` | `/ops/threat-intel/status` | IOC store health |
| `POST` | `/ops/threat-intel/refresh` | Force IOC feed refresh |
| `POST` | `/ops/garuda/process-retries` | Process Garuda retry queue |
| `WS` | `/ws/orchestrator` | WebSocket for real-time pipeline updates |

---

## Troubleshooting

### API server won't start

```
ModuleNotFoundError: No module named 'email_security'
```

**Fix:** Make sure `PYTHONPATH` includes the project root:

```bash
export PYTHONPATH=/home/LabsKraft/new_work
```

### ML model warm-up takes too long

First startup downloads and caches the transformer model. Subsequent starts are faster (~30s). Watch for:

```
Content ML model warmed up successfully.
```

### Agent not consuming messages

Check the agent log and verify AGENT_NAME is set:

```bash
tail -50 /tmp/header_agent.log
```

Common issue: Agent process exited silently. Restart it:

```bash
AGENT_NAME=header_agent nohup python -m email_security.agents.service_runner \
    > /tmp/header_agent.log 2>&1 &
```

### Report not ready (404 on /reports/{id})

- Check the orchestrator is running and consuming
- Check that all 7 agents delivered results (check `agent_outputs` in `/soc/overview`)
- The orchestrator waits up to 90 seconds (configurable) before finalizing with partial results

### RabbitMQ connection refused

```bash
docker ps | grep rabbitmq
# Ensure the container is healthy
docker compose -f docker/docker-compose.yml up -d rabbitmq
```

### Database connection error

```bash
docker ps | grep db
docker exec email-security-db pg_isready -U postgres
```

---

## Shutdown Procedure

### Local Development

```bash
# 1. Stop API server (Ctrl+C in Terminal 1)

# 2. Stop orchestrator (Ctrl+C in Terminal 3)

# 3. Stop parser worker if running (Ctrl+C in Terminal 4)

# 4. Kill all agent workers
pkill -f "email_security.agents.service_runner"

# 5. (Optional) Stop Docker infrastructure
cd /home/LabsKraft/new_work/email_security/docker
docker compose down
# Add -v to also remove volumes (clears all data):
# docker compose down -v
```

### Docker Deployment

```bash
cd /home/LabsKraft/new_work/email_security/docker
docker compose down        # stop containers, keep data
docker compose down -v     # stop containers AND delete volumes
```

---

## Quick Start — TL;DR

```bash
# Terminal 1 — Infrastructure
cd /home/LabsKraft/new_work/email_security/docker
docker compose up -d database redis rabbitmq

# Terminal 2 — API Server
cd /home/LabsKraft/new_work
source venv/bin/activate && export PYTHONPATH=$PWD
uvicorn email_security.api.main:app --host 0.0.0.0 --port 8000

# Terminal 3 — All 7 Agents
cd /home/LabsKraft/new_work
source venv/bin/activate && export PYTHONPATH=$PWD
for a in header_agent content_agent url_agent attachment_agent \
         sandbox_agent threat_intel_agent user_behavior_agent; do
    AGENT_NAME=$a nohup python -m email_security.agents.service_runner \
        > /tmp/${a}.log 2>&1 &
done

# Terminal 4 — Orchestrator
cd /home/LabsKraft/new_work
source venv/bin/activate && export PYTHONPATH=$PWD
python -m email_security.orchestrator.runner

# Open browser → http://localhost:8000/ui
```
