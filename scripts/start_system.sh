#!/usr/bin/env bash
# =============================================================================
# Agentic Email Security System – System Startup
# =============================================================================
# Starts the API server and optionally the parser/orchestrator workers.
#
# Usage:
#   chmod +x scripts/start_system.sh
#   ./scripts/start_system.sh              # Start API server only
#   ./scripts/start_system.sh --full       # Start API + parser + orchestrator
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

# Activate virtualenv if present
if [ -f "${PROJECT_ROOT}/venv/bin/activate" ]; then
    source "${PROJECT_ROOT}/venv/bin/activate"
fi

MODE="${1:---api}"

echo "============================================="
echo " Agentic Email Security – System Startup"
echo "============================================="
echo ""

# Ensure log and data directories exist
mkdir -p "${PROJECT_ROOT}/logs"
mkdir -p "${PROJECT_ROOT}/data"

case "$MODE" in
    --api)
        echo "[*] Starting API server..."
        echo "    Host: 0.0.0.0:8000"
        echo ""
        uvicorn email_security.api.main:app \
            --host 0.0.0.0 \
            --port 8000 \
            --reload \
            --log-level info
        ;;
    --full)
        echo "[*] Starting full system (API + Parser + Orchestrator)..."
        echo ""

        # Start parser worker in background
        echo "  → Starting parser worker..."
        python -m email_security.services.parser_worker &
        PARSER_PID=$!
        echo "    Parser PID: $PARSER_PID"

        # Start orchestrator worker in background
        echo "  → Starting orchestrator worker..."
        python -m email_security.orchestrator.runner &
        ORCH_PID=$!
        echo "    Orchestrator PID: $ORCH_PID"

        # Trap to clean up background processes on exit
        trap "echo 'Shutting down...'; kill $PARSER_PID $ORCH_PID 2>/dev/null; wait" EXIT

        # Start API server in foreground
        echo "  → Starting API server..."
        echo ""
        uvicorn email_security.api.main:app \
            --host 0.0.0.0 \
            --port 8000 \
            --log-level info
        ;;
    *)
        echo "Usage: $0 {--api|--full}"
        echo ""
        echo "  --api   Start API server only (default)"
        echo "  --full  Start API + parser worker + orchestrator worker"
        exit 1
        ;;
esac
