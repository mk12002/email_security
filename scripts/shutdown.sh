#!/usr/bin/env bash
# =============================================================================
# Agentic Email Security System – Shutdown
# =============================================================================
set -euo pipefail

echo "Stopping Fully Containerized Email Security System..."

# Determine project root (script is at email_security/scripts/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_DIR="$PROJECT_ROOT/email_security/docker"

if [ ! -d "$COMPOSE_DIR" ]; then
    echo "Error: compose directory not found: $COMPOSE_DIR" >&2
    exit 1
fi

cd "$COMPOSE_DIR"

# Preferred docker compose command
if docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE_CMD=(docker compose)
else
    DOCKER_COMPOSE_CMD=(docker-compose)
fi

"${DOCKER_COMPOSE_CMD[@]}" down "$@"

echo "All microservices and database backend successfully stopped."
