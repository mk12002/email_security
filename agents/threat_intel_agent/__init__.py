"""
Threat Intelligence Agent package.

Exposes the main analyze() entry point for the agent.
"""

from email_security.agents.threat_intel_agent.agent import analyze

__all__ = ["analyze"]
