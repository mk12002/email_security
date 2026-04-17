# Full System Run + SOC Validation Guide

This runbook starts backend, frontend UI, sandbox executor, all 7 agent workers, and the orchestrator so `.eml` uploads are fully processed and visible in the SOC dashboard.

## 1) Prerequisites

- Workspace root: `/home/LabsKraft/new_work`
- Python venv: `/home/LabsKraft/new_work/venv`
- RabbitMQ reachable from `.env` (`RABBITMQ_URL`)
- Redis reachable from `.env` (`REDIS_URL`)
- PostgreSQL reachable from `.env` (`DATABASE_URL`)
- Optional API auth:
  - If `API_AUTH_ENABLED=1`, you must set a valid API key in UI Settings (`X-API-Key`)

## 2) Start Services

Open separate terminals and run these commands from `/home/LabsKraft/new_work`.

### 2.1 Backend API (serves frontend too)

```bash
/home/LabsKraft/new_work/venv/bin/python -m uvicorn email_security.api.main:app --host 0.0.0.0 --port 8000
```

### 2.2 Sandbox Executor

```bash
/home/LabsKraft/new_work/venv/bin/python -m email_security.sandbox.executor_service
```

### 2.3 Agent Workers (7 terminals)

```bash
AGENT_NAME=header_agent /home/LabsKraft/new_work/venv/bin/python -m email_security.agents.service_runner
AGENT_NAME=content_agent /home/LabsKraft/new_work/venv/bin/python -m email_security.agents.service_runner
AGENT_NAME=url_agent /home/LabsKraft/new_work/venv/bin/python -m email_security.agents.service_runner
AGENT_NAME=attachment_agent /home/LabsKraft/new_work/venv/bin/python -m email_security.agents.service_runner
AGENT_NAME=sandbox_agent /home/LabsKraft/new_work/venv/bin/python -m email_security.agents.service_runner
AGENT_NAME=threat_intel_agent /home/LabsKraft/new_work/venv/bin/python -m email_security.agents.service_runner
AGENT_NAME=user_behavior_agent /home/LabsKraft/new_work/venv/bin/python -m email_security.agents.service_runner
```

### 2.4 Orchestrator Worker

```bash
/home/LabsKraft/new_work/venv/bin/python -m email_security.orchestrator.runner
```

## 3) Verify Core Endpoints

```bash
curl -sS http://127.0.0.1:8000/health
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/ui
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/ui/analyze
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/soc/dashboard
```

Expected:
- `/health` returns JSON with `status: healthy`
- UI routes return `200`

## 4) Upload a `.eml` and Poll Final Report

### 4.1 Upload

```bash
curl -sS -X POST http://127.0.0.1:8000/ingest-raw-email -F file=@email_security/dummy.eml
```

Copy `analysis_id` from the response.

### 4.2 Poll report

```bash
curl -sS http://127.0.0.1:8000/reports/<analysis_id>
```

Notes:
- `404` means report not ready yet; retry after a few seconds.
- `200` returns final decision with:
  - `agent_results`
  - `overall_risk_score`
  - `verdict`
  - `llm_explanation`
  - `counterfactual_result`
  - `threat_storyline`
  - `recommended_actions`

## 5) Validate SOC Dashboard Forwarding

### 5.1 Open dashboard

- Main SOC UI: `http://127.0.0.1:8000/soc/dashboard`
- JSON backing API: `http://127.0.0.1:8000/soc/overview`

### 5.2 What to verify after upload

- Queue health includes consumers for:
  - `header_agent.queue`
  - `content_agent.queue`
  - `url_agent.queue`
  - `attachment_agent.queue`
  - `sandbox_agent.queue`
  - `threat_intel_agent.queue`
  - `user_behavior_agent.queue`
  - `email.results.queue`
- `reports.recent` includes your latest `analysis_id`
- `reports.verdict_counts` updates
- `agent_outputs` includes per-agent rows for your analysis
- `response_actions` shows action counts (`deliver_with_banner`, `manual_review`, `soc_alert`, etc.)

## 6) Frontend Upload Flow

Use browser path `http://127.0.0.1:8000/ui/analyze`:

1. Upload `.eml`/`.msg`/`.txt`
2. Start analysis
3. Wait for live pipeline updates
4. View structured report
5. Cross-check same `analysis_id` in `/soc/dashboard`

## 7) Common Issues and Fixes

### Problem: `/reports/{analysis_id}` returns `500` with `relation "threat_reports" does not exist`

Cause:
- Orchestrator worker is not running, so schema/init and report persistence are not happening.

Fix:
- Start orchestrator:

```bash
/home/LabsKraft/new_work/venv/bin/python -m email_security.orchestrator.runner
```

### Problem: Upload accepted but no final report appears

Cause:
- Agent workers not running or not connected to RabbitMQ.

Fix:
- Start all 7 `service_runner` workers (Section 2.3)
- Check `/soc/overview` queue consumers

### Problem: UI calls return `401 Invalid API key`

Cause:
- `API_AUTH_ENABLED=1` and key missing/wrong.

Fix:
- Set key in UI Settings (top-right) or provide `X-API-Key` in API requests

## 8) Stop All Services

Use Ctrl+C in each service terminal.

If needed, force stop by process pattern:

```bash
pkill -f "uvicorn email_security.api.main:app"
pkill -f "email_security.sandbox.executor_service"
pkill -f "email_security.agents.service_runner"
pkill -f "email_security.orchestrator.runner"
```
