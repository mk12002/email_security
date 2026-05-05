"""
Attachment Static Analysis Agent package.

Exposes the main analyze() entry point for the agent.
"""

from email_security.src.agents.attachment_agent.agent import analyze

__all__ = ["analyze"]
