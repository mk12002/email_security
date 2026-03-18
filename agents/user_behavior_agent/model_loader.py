"""
Model loader for the User Interaction Prediction Agent.

Handles loading, caching, and version management of ML models.
"""

from pathlib import Path
from typing import Any, Optional

from services.logging_service import get_agent_logger

logger = get_agent_logger("user_behavior_agent")


class ModelLoader:
    """Loads and caches the ML model for user_behavior_agent."""

    def __init__(self, model_path: str = "models/user_behavior_agent/"):
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

        # Placeholder – model loading logic will be added in later phases
        self._model = None
        logger.warning("No trained model found; using placeholder")
        return self._model

    def is_loaded(self) -> bool:
        """Check whether the model is currently loaded."""
        return self._model is not None


def load_model(model_path: str = "models/user_behavior_agent/") -> Any:
    """Convenience function to load the agent model."""
    loader = ModelLoader(model_path)
    return loader.load_model()
