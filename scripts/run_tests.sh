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

# Activate virtualenv if present
if [ -f "${PROJECT_ROOT}/venv/bin/activate" ]; then
    source "${PROJECT_ROOT}/venv/bin/activate"
fi

SUITE="${1:-all}"

echo "============================================="
echo " Agentic Email Security – Test Runner"
echo "============================================="
echo ""

case "$SUITE" in
    unit)
        echo "[*] Running unit tests..."
        pytest tests/unit/ -v --tb=short "$@"
        ;;
    integration)
        echo "[*] Running integration tests..."
        pytest tests/integration/ -v --tb=short "$@"
        ;;
    smoke)
        echo "[*] Running smoke tests..."
        pytest tests/ -v -m smoke --tb=short "$@"
        ;;
    all)
        echo "[*] Running all tests..."
        pytest tests/ -v --tb=short
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
