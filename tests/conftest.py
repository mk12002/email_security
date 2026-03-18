"""Pytest shared setup for consistent import paths."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
EMAIL_SECURITY_ROOT = Path(__file__).resolve().parents[1]

for entry in (str(REPO_ROOT), str(EMAIL_SECURITY_ROOT)):
    if entry not in sys.path:
        sys.path.insert(0, entry)
