#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VENV_DIR="${PROJECT_ROOT}/venv"
PYTHON_BIN="${PYTHON_BIN:-python3}"

echo "============================================="
echo " Agentic Email Security – Ubuntu Setup"
echo "============================================="

if ! command -v sudo >/dev/null 2>&1; then
  echo "ERROR: sudo is required for apt package installation."
  exit 1
fi

echo "[1/6] Installing Ubuntu system dependencies..."
sudo apt-get update
sudo apt-get install -y \
  build-essential \
  python3-dev \
  python3-venv \
  libssl-dev \
  libffi-dev \
  libfuzzy-dev \
  libmagic-dev \
  pkg-config \
  git \
  curl

echo "[2/6] Checking Python version..."
PYTHON_VERSION=$($PYTHON_BIN --version 2>&1 | awk '{print $2}')
PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)
if [ "$PYTHON_MAJOR" -lt 3 ] || { [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 11 ]; }; then
  echo "ERROR: Python 3.11+ is required. Found: $PYTHON_VERSION"
  exit 1
fi
echo "  ✓ Python $PYTHON_VERSION detected"

echo "[3/6] Creating virtual environment..."
if [ ! -d "$VENV_DIR" ]; then
  $PYTHON_BIN -m venv "$VENV_DIR"
fi
source "${VENV_DIR}/bin/activate"

echo "[4/6] Installing Python packages..."
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r "${PROJECT_ROOT}/requirements.txt"

echo "[5/6] Preparing config and directories..."
if [ ! -f "${PROJECT_ROOT}/.env" ]; then
  cp "${PROJECT_ROOT}/.env.template" "${PROJECT_ROOT}/.env"
fi
mkdir -p "${PROJECT_ROOT}/logs" "${PROJECT_ROOT}/datasets_processed" "${PROJECT_ROOT}/threat_intelligence"

echo "[6/6] Quick validation commands..."
echo "  source venv/bin/activate"
echo "  pytest tests/"
echo "  cd docker && docker compose up --build"

echo ""
echo "Ubuntu setup complete."
