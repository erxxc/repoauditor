"""Shared LLM client — the reliability wrapper every stage routes its calls through.

Responsibilities (identical for map / detect / falsify / normalize):

1. **Validate** the backend's raw response against the stage's Pydantic model.
2. **Retry**, bounded (`config.llm.max_retries`, default 2), feeding the validation
   error back into the retry prompt.
3. On exhaustion, **log a `ValidationFailure`** to `store/` and **raise** — the client
   never swallows a hard failure; the calling stage decides what to do with it.
4. **Confidence-gate**: if validation succeeds but the model's own reported confidence
   is below `config.llm.confidence_threshold`, return `low_confidence=True` rather than
   a confident result. The client does NOT decide the fallback strategy (broader
   retrieval vs `unresolved`) — that is stage-specific.

The client is prompt-agnostic (no prompts live under `llm/`); each call passes the
stage's `module` name and `prompt_version` so failures are attributable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Generic, TypeVar

from pydantic import BaseModel, ValidationError

from ..config import Config, get_config
from ..store import db
from ..store.models import ValidationFailure
from .backends import AnthropicBackend, Backend, BackendError, OpenAICompatibleBackend

T = TypeVar("T", bound=BaseModel)

_RAW_TRUNCATE = 2000


class LLMValidationError(RuntimeError):
    """Raised when a call fails validation after all bounded retries are exhausted."""


@dataclass
class Completion(Generic[T]):
    """A validated model result plus its confidence signal.

    `low_confidence` is True when the model reported a confidence below the configured
    threshold — the caller must then re-score with broader context or persist
    `unresolved`, never treat `value` as a confident result.
    """

    value: T
    confidence: float | None
    low_confidence: bool


def _reported_confidence(value: BaseModel) -> float | None:
    """The model's own top-level `confidence` field, if it reports one."""
    c = getattr(value, "confidence", None)
    return float(c) if isinstance(c, (int, float)) else None


def _short(text: str) -> str:
    return text[:_RAW_TRUNCATE]


class LLMClient:
    """Wraps a `Backend` with validation, bounded retry, and confidence gating."""

    def __init__(self, backend: Backend, config: Config | None = None):
        self._backend = backend
        self._config = config or get_config()

    def call(
        self,
        *,
        module: str,
        prompt_version: str,
        system: str,
        user: str,
        schema: type[T],
        context: dict | None = None,
    ) -> Completion[T]:
        """Call the model for `schema`, validating + retrying; return a `Completion`.

        `module` and `prompt_version` attribute any logged `ValidationFailure`.
        """
        ctx = context or {}
        threshold = self._config.llm.confidence_threshold
        max_retries = self._config.llm.max_retries

        last_error = "no response"
        last_raw = ""
        attempt_user = user

        for _ in range(max_retries + 1):
            try:
                raw = self._backend.complete(
                    system=system, user=attempt_user, schema=schema, context=ctx
                )
            except BackendError as exc:
                last_error, last_raw = str(exc), exc.raw
            else:
                last_raw = raw
                try:
                    value = schema.model_validate_json(raw)
                except ValidationError as exc:
                    last_error = _short(str(exc))
                else:
                    confidence = _reported_confidence(value)
                    low = confidence is not None and confidence < threshold
                    return Completion(value=value, confidence=confidence, low_confidence=low)

            # Feed the validation error back into the next attempt's prompt.
            attempt_user = (
                f"{user}\n\n[Your previous response was invalid: {last_error}\n"
                f"Return ONLY data matching the required schema.]"
            )

        db.insert_validation_failure(
            ValidationFailure(
                module=module,
                prompt_version=prompt_version,
                raw_response=_short(last_raw),
                validation_error=last_error,
            ),
            self._config,
        )
        raise LLMValidationError(
            f"{module}: response failed validation after {max_retries + 1} attempts "
            f"({prompt_version}): {last_error}"
        )


def get_llm_client(config: Config | None = None) -> LLMClient:
    """Build the configured production client. Tests inject a scripted backend."""
    config = config or get_config()
    backend: Backend
    if config.llm.provider == "openai-compatible":
        backend = OpenAICompatibleBackend(config)
    else:
        backend = AnthropicBackend(config)
    return LLMClient(backend, config)
