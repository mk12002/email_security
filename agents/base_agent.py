"""
Shared base class for all asynchronous email analysis agents.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from email_security.configs.settings import settings
from email_security.services.logging_service import get_agent_logger
from email_security.services.messaging_service import RabbitMQClient


class BaseAgent(ABC):
    """Base RabbitMQ consumer for NewEmailEvent processing."""

    def __init__(self, agent_name: str):
        self.agent_name = agent_name
        self.logger = get_agent_logger(agent_name)
        self.messaging = RabbitMQClient()
        self.queue_name = f"{agent_name}.queue"

    @abstractmethod
    def analyze(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Return standardized agent result dictionary."""

    def _handle_message(self, payload: dict[str, Any]) -> None:
        analysis_id = payload.get("analysis_id")
        self.logger.info("Processing event", analysis_id=analysis_id)
        result = self.analyze(payload)
        result["analysis_id"] = analysis_id
        self.messaging.publish_to_queue(settings.results_queue, result)
        self.logger.info(
            "Published agent result",
            analysis_id=analysis_id,
            risk_score=result.get("risk_score", 0.0),
        )

    def run(self) -> None:
        self.messaging.connect()
        self.messaging.declare_new_email_fanout(self.queue_name)
        self.messaging.declare_results_queue(settings.results_queue)
        self.logger.info("Agent worker started", queue=self.queue_name)
        self.messaging.consume(self.queue_name, self._handle_message)
