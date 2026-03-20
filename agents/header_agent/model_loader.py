"""
Model loader for the Header Analysis Agent.

Handles loading, caching, and version management of ML models.
"""

from pathlib import Path
from typing import Any, Optional

import joblib

from services.logging_service import get_agent_logger

logger = get_agent_logger("header_agent")


class ModelLoader:
    """Loads and caches the ML model for header_agent."""

    def __init__(self, model_path: str = "models/header_agent/model.joblib"):
        self.model_path = Path(model_path)
        self._model: Optional[Any] = None

    def load_model(self) -> Any:
        """
        Load the model from disk.

        Returns:
            The loaded model object, or None if not yet trained.
        """
        if self._model is not None:
            return self._model

        logger.info("Loading model", path=str(self.model_path))

        if not self.model_path.exists():
            logger.warning("No trained model found; using placeholder")
            return None

        try:
            bundle = joblib.load(self.model_path)
            self._model = bundle.get("model")
            logger.info("Model loaded successfully")
        except Exception as e:
            logger.warning("Failed to load header model", error=str(e))
            self._model = None

        return self._model

    def is_loaded(self) -> bool:
        """Check whether the model is currently loaded."""
        return self._model is not None


def load_model(model_path: str = "models/header_agent/model.joblib") -> Any:
    """Convenience function to load the agent model."""
    loader = ModelLoader(model_path)
    return loader.load_model()
