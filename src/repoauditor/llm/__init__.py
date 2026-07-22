"""Shared LLM client for the techniques-driven stages.

Every LLM call in map/detect/falsify/normalize goes through `LLMClient`, which
validates against the stage's Pydantic model, retries (bounded) on failure, logs a
`ValidationFailure` on exhaustion, and confidence-gates the result. Backends
(`AnthropicBackend`, `ScriptedBackend`) only produce raw model text.
"""

from .backends import (
    AnthropicBackend,
    Backend,
    BackendError,
    OpenAICompatibleBackend,
    ScriptedBackend,
)
from .client import Completion, LLMClient, LLMValidationError, get_llm_client

__all__ = [
    "LLMClient",
    "Completion",
    "LLMValidationError",
    "get_llm_client",
    "Backend",
    "BackendError",
    "AnthropicBackend",
    "OpenAICompatibleBackend",
    "ScriptedBackend",
]
