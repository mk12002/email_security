#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

echo "Starting fully containerized Email Security System..."

# Determine project root (script is at email_security/scripts/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
EMAIL_SEC_DIR="$PROJECT_ROOT/email_security"

# Provision logging and data directories under project root
LOG_DIR="$EMAIL_SEC_DIR/logs"
DATA_DIR="$EMAIL_SEC_DIR/data"
mkdir -p "$LOG_DIR" "$DATA_DIR"
chmod 775 "$LOG_DIR" "$DATA_DIR" || true

# Ensure docker is available
if ! command -v docker >/dev/null 2>&1; then
	echo "Error: docker is not installed or not in PATH." >&2
	exit 1
fi

# Prefer 'docker compose' (v2) if available, otherwise fall back to 'docker-compose'
if docker compose version >/dev/null 2>&1; then
	DOCKER_COMPOSE_CMD=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
	DOCKER_COMPOSE_CMD=(docker-compose)
else
	echo "Error: neither 'docker compose' nor 'docker-compose' is available." >&2
	exit 1
fi

COMPOSE_DIR="$EMAIL_SEC_DIR/docker"
if [ ! -d "$COMPOSE_DIR" ]; then
	echo "Error: compose directory not found: $COMPOSE_DIR" >&2
	exit 1
fi

echo "Using compose dir: $COMPOSE_DIR"
cd "$COMPOSE_DIR"

echo "Building and starting containers (detached). This may take a few minutes..."
# Try to use --wait when supported; if it fails, retry without it.
set +e
"${DOCKER_COMPOSE_CMD[@]}" up -d --build --wait
RC=$?
set -e
if [ $RC -ne 0 ]; then
	echo "Initial 'up' with --wait failed (exit $RC). Retrying without --wait..."
	"${DOCKER_COMPOSE_CMD[@]}" up -d --build
fi

echo "Waiting briefly for services to report healthy..."
sleep 10

echo "Startup complete. Verify status: ${DOCKER_COMPOSE_CMD[*]} ps"
echo "Stream logs: ${DOCKER_COMPOSE_CMD[*]} logs -f --tail=200"

exit 0
