"""Pytest shared setup for consistent import paths."""

from __future__ import annotations

import sys
from pathlib import Path
import importlib

REPO_ROOT = Path(__file__).resolve().parents[2]
EMAIL_SECURITY_ROOT = Path(__file__).resolve().parents[1]

for entry in (str(REPO_ROOT), str(EMAIL_SECURITY_ROOT)):
    if entry not in sys.path:
        sys.path.insert(0, entry)

# Ensure local "datasets" package wins over third-party packages with same name.
existing = sys.modules.get("datasets")
if existing is not None:
    existing_file = str(getattr(existing, "__file__", "") or "")
    if existing_file and "site-packages" in existing_file.lower():
        del sys.modules["datasets"]

importlib.invalidate_caches()
