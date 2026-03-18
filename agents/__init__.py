"""
Agents package for the Agentic Email Security System.

Each sub-package contains an independent AI agent that analyzes
a specific aspect of an email for phishing detection.
"""

from agents.header_agent import analyze as header_analyze
from agents.content_agent import analyze as content_analyze
from agents.url_agent import analyze as url_analyze
from agents.attachment_agent import analyze as attachment_analyze
from agents.sandbox_agent import analyze as sandbox_analyze
from agents.threat_intel_agent import analyze as threat_intel_analyze
from agents.user_behavior_agent import analyze as user_behavior_analyze

AGENT_REGISTRY = {
    "header_agent": header_analyze,
    "content_agent": content_analyze,
    "url_agent": url_analyze,
    "attachment_agent": attachment_analyze,
    "sandbox_agent": sandbox_analyze,
    "threat_intel_agent": threat_intel_analyze,
    "user_behavior_agent": user_behavior_analyze,
}

__all__ = ["AGENT_REGISTRY"]
