"""Configuration management for the Agentic Email Security System.

Expose the `settings` singleton directly from the package so consumers can
`from email_security.src.configs import settings` and receive the
Pydantic `settings` instance rather than the submodule object.
"""

# Import the settings submodule and re-export the `settings` instance.
from . import settings as _settings  # noqa: F401

# `settings` instance (Pydantic BaseSettings singleton)
settings = getattr(_settings, "settings")

__all__ = ["settings"]
