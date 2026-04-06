#!/usr/bin/env bash
# =============================================================================
# Agentic Email Security System – Development Environment Setup
# =============================================================================
# This script creates a Python virtual environment, installs all dependencies,
# initialises the .env file, and prepares the log directory.
#
# Usage:
#   chmod +x scripts/setup_env.sh
#   ./scripts/setup_env.sh
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VENV_DIR="${PROJECT_ROOT}/venv"
PYTHON_BIN="${PYTHON_BIN:-python3}"

echo "============================================="
echo " Agentic Email Security – Environment Setup"
echo "============================================="
echo ""

# ---- Check Python version ----
echo "[1/5] Checking Python version..."
PYTHON_VERSION=$($PYTHON_BIN --version 2>&1 | awk '{print $2}')
PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || { [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 10 ]; }; then
    echo "ERROR: Python 3.10+ is required. Found: $PYTHON_VERSION"
    exit 1
fi
echo "  ✓ Python $PYTHON_VERSION detected"

# ---- Create virtual environment ----
echo ""
echo "[2/5] Creating virtual environment at ${VENV_DIR}..."
if [ -d "$VENV_DIR" ]; then
    echo "  ⚠ Virtual environment already exists. Skipping creation."
else
    $PYTHON_BIN -m venv "$VENV_DIR"
    echo "  ✓ Virtual environment created"
fi

# ---- Activate and install dependencies ----
echo ""
echo "[3/5] Installing Python dependencies..."
source "${VENV_DIR}/bin/activate"
pip install --upgrade pip setuptools wheel > /dev/null 2>&1
pip install -r "${PROJECT_ROOT}/requirements.txt"
echo "  ✓ Dependencies installed"

# ---- Create .env from template ----
echo ""
echo "[4/5] Setting up environment configuration..."
if [ -f "${PROJECT_ROOT}/.env" ]; then
    echo "  ⚠ .env file already exists. Skipping."
else
    cp "${PROJECT_ROOT}/.env.template" "${PROJECT_ROOT}/.env"
    echo "  ✓ .env file created from template"
    echo "  → Edit .env to add your API keys and connection strings"
fi

# ---- Create log directory ----
echo ""
echo "[5/5] Preparing directories..."
mkdir -p "${PROJECT_ROOT}/logs"
mkdir -p "${PROJECT_ROOT}/datasets_processed"
mkdir -p "${PROJECT_ROOT}/threat_intelligence"
echo "  ✓ Directories ready"

# ---- Done ----
echo ""
echo "============================================="
echo " Setup complete!"
echo "============================================="
echo ""
echo " To activate the virtual environment:"
echo "   source venv/bin/activate"
echo ""
echo " To start the API server:"
echo "   uvicorn email_security.api.main:app --reload --host 0.0.0.0 --port 8000"
echo ""
echo " To run tests:"
echo "   pytest tests/"
echo ""
