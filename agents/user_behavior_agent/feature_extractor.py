"""Feature extraction for user interaction prediction models."""

from __future__ import annotations

from typing import Any
import sqlite3
from pathlib import Path

from email_security.services.logging_service import get_agent_logger
from email_security.preprocessing.user_behavior_feature_contract import extract_behavior_features

logger = get_agent_logger("user_behavior_agent")

_DB_PATH = Path("data/behavior_graph.db")

class BehaviorGraphStore:
    def __init__(self, db_path: Path = _DB_PATH):
        self.db_path = db_path
        self._conn = None
        
    def _get_cursor(self) -> sqlite3.Cursor:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        return self._conn.cursor()
        
    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

_STORE = BehaviorGraphStore()

def extract_features(data: dict[str, Any]) -> dict[str, Any]:
    """Bridge runtime payload to the exact deterministic contract used in offline training."""
    logger.debug("Extracting behavioral features mapping against local graph", agent="user_behavior_agent")
    
    try:
        cursor = _STORE._get_cursor()
        features = extract_behavior_features(data, cursor)
        return features
    except Exception as e:
        logger.error("Failed to extract behavior features: {}", e)
        # Fallback empty structure
        return {"numeric_vector": None, "context": {}}
