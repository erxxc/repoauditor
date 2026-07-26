"""Shared LLM client — the reliability wrapper every stage routes its calls through.

Responsibilities (identical for map / detect / falsify / normalize):

1. **Validate** the backend's raw response against the stage's Pydantic model.
2. **Retry**, bounded (`config.llm.max_retries`, default 2), for validation failures and
   plausibly transient transport/5xx failures. Authentication, permission, invalid-model,
   quota, and other terminal client errors stop immediately.
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

import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Iterator
from typing import Generic, TypeVar

from pydantic import BaseModel, ValidationError

from ..config import Config, get_config
from ..store import db
from ..store.models import ModelUsage, ValidationFailure
from .backends import AnthropicBackend, Backend, BackendError, OpenAICompatibleBackend

T = TypeVar("T", bound=BaseModel)

_RAW_TRUNCATE = 2000


class LLMValidationError(RuntimeError):
    """Raised when a call fails validation after all bounded retries are exhausted."""


class LLMBudgetExceeded(RuntimeError):
    """Raised before a request that would continue an exhausted pipeline budget."""


_pipeline_run_id: ContextVar[int | None] = ContextVar(
    "repoauditor_pipeline_run_id", default=None
)


@contextmanager
def model_usage_scope(pipeline_run_id: int) -> Iterator[None]:
    """Attribute model calls in this context to one durable pipeline run."""
    token = _pipeline_run_id.set(pipeline_run_id)
    try:
        yield
    finally:
        _pipeline_run_id.reset(token)


def remaining_pipeline_call_capacity(config: Config | None = None) -> int | None:
    """Return authoritative remaining provider-call capacity for the active run.

    ``None`` means there is no active pipeline scope or the call ceiling is disabled.
    Token capacity is intentionally not estimated here: provider token usage is only
    authoritative after a response, and the regular pre-request circuit breaker remains
    responsible for enforcing that independent ceiling.
    """
    pipeline_run_id = _pipeline_run_id.get()
    config = config or get_config()
    maximum = config.llm.max_calls_per_pipeline_run
    if pipeline_run_id is None or maximum == 0:
        return None
    used = db.summarize_model_usage(pipeline_run_id, config)["calls"]
    return max(0, maximum - used)


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

    @property
    def sampling_seed(self) -> int | None:
        """Backend-reported deterministic seed, or None when no seed is supported."""
        return getattr(self._backend, "sampling_seed", None)

    def _check_pipeline_budget(self, pipeline_run_id: int | None) -> None:
        if pipeline_run_id is None:
            return
        totals = db.summarize_model_usage(pipeline_run_id, self._config)
        max_calls = self._config.llm.max_calls_per_pipeline_run
        max_tokens = self._config.llm.max_tokens_per_pipeline_run
        processed_tokens = (
            totals["input_tokens"] + totals["output_tokens"]
            + totals["cache_read_tokens"] + totals["cache_write_tokens"]
        )
        if max_calls and totals["calls"] >= max_calls:
            raise LLMBudgetExceeded(
                f"LLM call budget exhausted for pipeline run #{pipeline_run_id}: "
                f"{totals['calls']}/{max_calls} provider calls; raise "
                "[llm].max_calls_per_pipeline_run before resuming"
            )
        if max_tokens and processed_tokens >= max_tokens:
            raise LLMBudgetExceeded(
                f"LLM token budget exhausted for pipeline run #{pipeline_run_id}: "
                f"{processed_tokens}/{max_tokens} provider-reported tokens; raise "
                "[llm].max_tokens_per_pipeline_run before resuming"
            )

    def _record_usage(
        self, *, pipeline_run_id: int | None, module: str, prompt_version: str,
        context: dict, latency_ms: int,
    ) -> None:
        if not getattr(self._backend, "tracks_usage", False):
            return
        usage = getattr(self._backend, "last_usage", None)
        db.insert_model_usage(
            ModelUsage(
                pipeline_run_id=pipeline_run_id,
                stage=str(context.get("stage") or module),
                module=module,
                prompt_version=prompt_version,
                provider=self._config.llm.provider,
                model=self._config.model.name,
                usage_available=usage is not None,
                input_tokens=usage.input_tokens if usage is not None else None,
                output_tokens=usage.output_tokens if usage is not None else None,
                cache_read_tokens=usage.cache_read_tokens if usage is not None else None,
                cache_write_tokens=usage.cache_write_tokens if usage is not None else None,
                latency_ms=latency_ms,
            ),
            self._config,
        )

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
        pipeline_run_id = _pipeline_run_id.get()

        for _ in range(max_retries + 1):
            self._check_pipeline_budget(pipeline_run_id)
            started = time.monotonic()
            try:
                raw = self._backend.complete(
                    system=system, user=attempt_user, schema=schema, context=ctx
                )
            except BackendError as exc:
                last_error, last_raw = str(exc), exc.raw
                self._record_usage(
                    pipeline_run_id=pipeline_run_id,
                    module=module,
                    prompt_version=prompt_version,
                    context=ctx,
                    latency_ms=max(0, round((time.monotonic() - started) * 1000)),
                )
                if not exc.retryable:
                    raise
            else:
                self._record_usage(
                    pipeline_run_id=pipeline_run_id,
                    module=module,
                    prompt_version=prompt_version,
                    context=ctx,
                    latency_ms=max(0, round((time.monotonic() - started) * 1000)),
                )
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
