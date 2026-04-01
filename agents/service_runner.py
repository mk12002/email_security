"""
Container entrypoint for agent workers.
"""

from __future__ import annotations

import os
from typing import Any, Callable

from agents.base_agent import BaseAgent
from agents.header_agent import analyze as header_analyze
from agents.content_agent import analyze as content_analyze
from agents.url_agent import analyze as url_analyze
from agents.attachment_agent import analyze as attachment_analyze
from agents.sandbox_agent import analyze as sandbox_analyze
from agents.threat_intel_agent import analyze as threat_intel_analyze
from configs.settings import settings
from services.logging_service import setup_logging

AGENT_FUNCTIONS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "header_agent": header_analyze,
    "content_agent": content_analyze,
    "url_agent": url_analyze,
    "attachment_agent": attachment_analyze,
    "sandbox_agent": sandbox_analyze,
    "threat_intel_agent": threat_intel_analyze,
}


class FunctionalAgent(BaseAgent):
    """Wrap plain analyze(payload) callables into BaseAgent consumers."""

    def __init__(self, agent_name: str, fn: Callable[[dict[str, Any]], dict[str, Any]]):
        super().__init__(agent_name)
        self.fn = fn

    def analyze(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self.fn(payload)


def run() -> None:
    setup_logging(settings.log_dir, settings.app_log_level, settings.log_format)
    agent_name = os.getenv("AGENT_NAME", "").strip()
    if agent_name not in AGENT_FUNCTIONS:
        raise ValueError(f"Unsupported AGENT_NAME={agent_name}. Expected one of: {sorted(AGENT_FUNCTIONS)}")

    agent = FunctionalAgent(agent_name=agent_name, fn=AGENT_FUNCTIONS[agent_name])
    agent.run()


if __name__ == "__main__":
    run()
