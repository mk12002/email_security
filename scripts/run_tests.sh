#!/usr/bin/env bash
# =============================================================================
# Agentic Email Security System – Test Runner
# =============================================================================
# Runs the full test suite with proper configuration.
#
# Usage:
#   chmod +x scripts/run_tests.sh
#   ./scripts/run_tests.sh              # Run all tests
#   ./scripts/run_tests.sh unit         # Run only unit tests
#   ./scripts/run_tests.sh integration  # Run only integration tests
#   ./scripts/run_tests.sh smoke        # Run only smoke-marked tests
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

# Activate virtualenv if present — check project-level and parent-directory
if [ -f "${PROJECT_ROOT}/venv/bin/activate" ]; then
    source "${PROJECT_ROOT}/venv/bin/activate"
elif [ -f "$(dirname "$PROJECT_ROOT")/venv/bin/activate" ]; then
    source "$(dirname "$PROJECT_ROOT")/venv/bin/activate"
fi

SUITE="${1:-all}"

# Shift the first arg so remaining args can be passed through
if [ $# -gt 0 ]; then shift; fi

echo "============================================="
echo " Agentic Email Security – Test Runner"
echo "============================================="
echo " Python: $(python3 --version 2>&1)"
echo " Interpreter: $(which python3)"
echo ""

case "$SUITE" in
    unit)
        echo "[*] Running unit tests..."
        python3 -m pytest tests/unit/ -v --tb=short "$@"
        ;;
    integration)
        echo "[*] Running integration tests..."
        python3 -m pytest tests/integration/ -v --tb=short "$@"
        ;;
    smoke)
        echo "[*] Running smoke tests..."
        python3 -m pytest tests/ -v -m smoke --tb=short "$@"
        ;;
    all)
        echo "[*] Running all tests..."
        python3 -m pytest tests/ -v --tb=short "$@"
        ;;
    *)
        echo "Usage: $0 {unit|integration|smoke|all}"
        exit 1
        ;;
esac

echo ""
echo "============================================="
echo " Tests complete."
echo "============================================="
