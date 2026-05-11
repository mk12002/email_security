# Agentic Email Security System - Startup Guide

> Last Updated: May 7, 2026

## Is `startup.sh` Sufficient?

Yes, for full containerized startup.

- Use `scripts/startup.sh` when you want the complete Docker stack (API, parser, orchestrator, all agents, DB, Redis, RabbitMQ).
- Use `scripts/start_system.sh` only for local Python-process mode (`--api` or `--full`), not for full Docker lifecycle.

When I run extra `docker compose` commands, that is usually for post-start verification (health, logs, queues), not because startup failed.

## Recommended Way To Start The Entire System

```bash
cd /home/LabsKraft/new_work/email_security
chmod +x scripts/startup.sh
./scripts/startup.sh
```

What this script does:

1. Ensures required directories exist (`logs`, `data`).
2. Detects compose command (`docker compose` preferred).
3. Runs compose startup with build.
4. Waits briefly and prints verification hints.

## Optional Startup Modes

### Full Docker (direct compose)

```bash
cd /home/LabsKraft/new_work/email_security/docker
docker compose up -d --build
```

### Local Python processes (non-container app runtime)

```bash
cd /home/LabsKraft/new_work/email_security
chmod +x scripts/start_system.sh
./scripts/start_system.sh --full
```

## Immediate Post-Start Verification

```bash
cd /home/LabsKraft/new_work/email_security/docker
docker compose ps
```

Healthy baseline:

- `api_service` should be `healthy`.
- `rabbitmq`, `database`, `redis` should be `healthy`.
- `orchestrator_service`, `parser_service`, and all 7 agent services should be `Up`.

Queue health:

```bash
cd /home/LabsKraft/new_work/email_security/docker
docker compose exec -T rabbitmq rabbitmqctl list_queues name messages consumers
```

Expected steady state for active flow:

- Agent queues have `consumers >= 1`.
- No unbounded queue growth.

## User Interfaces & Observability

Access the following web-based interfaces for real-time monitoring and interaction:

### 🌐 Primary Interfaces
- **Main Control Center**: [http://localhost:8000/ui](http://localhost:8000/ui) — *Central landing page for system navigation.*
- **SOC Intelligence Dashboard**: [http://localhost:8000/soc/dashboard](http://localhost:8000/soc/dashboard) — *Real-time threat metrics, risk distributions, and response status.*
- **Email Analysis Tool**: [http://localhost:8000/ui/analyze](http://localhost:8000/ui/analyze) — *Manual file upload for instant email analysis.*
- **Agent Testing Lab**: [http://localhost:8000/ui/agents](http://localhost:8000/ui/agents) — *Isolated testing of individual AI agents with custom payloads.*

### 🛠️ Developer & Health Tools
- **API Documentation (Swagger)**: [http://localhost:8000/docs](http://localhost:8000/docs) — *Interactive API exploration.*
- **Prometheus Metrics**: [http://localhost:8000/metrics](http://localhost:8000/metrics) — *Raw telemetry for Prometheus scraping and health monitoring.*
- **OpenAPI JSON**: [http://localhost:8000/openapi.json](http://localhost:8000/openapi.json)

## Core Endpoints You Will Use Most

- `GET /health`
- `GET /metrics`
- `POST /ingest-raw-email`
- `POST /analyze-email`
- `GET /reports/{analysis_id}`
- `GET /ui`
- `GET /ui/analyze`
- `GET /ui/agents`
- `GET /soc/dashboard`
- `GET /soc/overview`

## Health Checks

### API + Broker Health

```bash
curl -s http://localhost:8000/health | python3 -m json.tool
```

Look for:

- `status`: `healthy` or `degraded`
- `rabbitmq.status`: `healthy`
- `rabbitmq.queue_depths` present

### Live E2E Sanity Check

```bash
FILE=/home/LabsKraft/new_work/test_phishing_from_host.eml
INGEST_RESP=$(curl -s -X POST -F "file=@$FILE" http://localhost:8000/ingest-raw-email)
echo "$INGEST_RESP"
```

Then poll:

```bash
ANALYSIS_ID=$(printf '%s' "$INGEST_RESP" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("analysis_id",""))')
curl -s "http://localhost:8000/reports/$ANALYSIS_ID" | python3 -m json.tool
```

## Prometheus and Metrics Validation

### App metrics endpoint

```bash
curl -s http://localhost:8000/metrics | head -n 80
```

You should see standard and custom metrics (for example RabbitMQ publish/consume histograms).

### Quick metric presence checks

```bash
curl -s http://localhost:8000/metrics | grep -E "rabbitmq_publish_duration_ms|rabbitmq_consume_duration_ms|rabbitmq_active_connections" || true
```

### Optional: run a temporary Prometheus to scrape `/metrics`

Create scrape config:

```bash
cat >/tmp/emailsec-prometheus.yml <<'YAML'
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: email_security_api
    static_configs:
      - targets: ['host.docker.internal:8000']
YAML
```

Run Prometheus:

```bash
docker run --rm -d --name emailsec-prom \
  --add-host=host.docker.internal:host-gateway \
  -p 9090:9090 \
  -v /tmp/emailsec-prometheus.yml:/etc/prometheus/prometheus.yml:ro \
  prom/prometheus
```

Open:

- Prometheus UI: `http://localhost:9090`
- Example query: `rabbitmq_publish_duration_ms_count`

Stop temporary Prometheus:

```bash
docker stop emailsec-prom
```

## Useful Runtime Observability Commands

```bash
cd /home/LabsKraft/new_work/email_security/docker
docker compose logs -f --tail=200 api_service
docker compose logs -f --tail=200 orchestrator_service
docker compose logs -f --tail=200 attachment_agent_service
docker compose logs -f --tail=200 sandbox_agent_service
```

```bash
cd /home/LabsKraft/new_work/email_security/docker
docker compose logs --since 15m | grep -E "AMQPHeartbeatTimeout|StreamLostError|Traceback|ERROR"
```

## Shutdown

Containerized stack:

```bash
cd /home/LabsKraft/new_work/email_security/docker
docker compose down
```

Remove volumes too (destructive):

```bash
cd /home/LabsKraft/new_work/email_security/docker
docker compose down -v
```

## Troubleshooting Notes

- If startup appears fine but reports stay at 404, check `orchestrator_service` logs and queue consumers.
- If API health is degraded, inspect RabbitMQ connectivity first.
- If ingestion works but final actions fail, check Garuda/Graph integration endpoints and credentials.
