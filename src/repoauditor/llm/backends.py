"""Model backends: the raw "call the model, return its text" layer.

A backend's only job is to produce the model's raw response for a prompt. All
validation, bounded retry, confidence gating, and failure logging live one level up
in `client.py` — so the reliability behaviour is identical regardless of which
backend is in use.

* `AnthropicBackend` — production, via the official SDK's structured outputs.
* `ScriptedBackend` — deterministic test double; a handler returns a model (serialized
  to JSON) or a raw string (to exercise the client's validation-failure path).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Protocol, runtime_checkable

import httpx
from pydantic import BaseModel, ValidationError

from ..config import Config, get_config


class BackendError(RuntimeError):
    """The backend produced no usable response (refusal, empty output)."""

    def __init__(self, message: str, raw: str = "", *, retryable: bool = True):
        super().__init__(message)
        self.raw = raw
        self.retryable = retryable


@dataclass(frozen=True)
class BackendUsage:
    """Usage fields reported by the provider for one completed request."""

    input_tokens: int
    output_tokens: int
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0


@runtime_checkable
class Backend(Protocol):
    """Produce the model's raw JSON response for a prompt targeting `schema`."""

    def complete(self, *, system: str, user: str, schema: type[BaseModel], context: dict) -> str:
        ...


class AnthropicBackend:
    """Production backend backed by the official Anthropic SDK (structured outputs).

    `claude-opus-4-8` rejects sampling params and `budget_tokens`, so none are sent —
    behaviour is steered by the versioned prompts. Returns the parsed model's JSON so
    the client re-validates it against `schema` uniformly.
    """

    def __init__(self, config: Config | None = None):
        import anthropic  # lazy: importing this module never requires the SDK

        self._config = config or get_config()
        self._anthropic = anthropic
        # The shared LLM client is the sole owner of retry count. Disabling the SDK's
        # hidden retries keeps configured budgets and persisted attempt counts exact.
        self._client = anthropic.Anthropic(
            timeout=self._config.llm.timeout_seconds,
            max_retries=0,
        )
        self.sampling_seed: int | None = None
        self.last_usage: BackendUsage | None = None
        self.tracks_usage = True

    def complete(self, *, system: str, user: str, schema: type[BaseModel], context: dict) -> str:
        self.last_usage = None
        try:
            response = self._client.messages.parse(
                model=self._config.model.name,
                max_tokens=self._config.model.max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
                output_format=schema,
            )
        except ValidationError as exc:
            # The Anthropic SDK validates structured output before returning the
            # response. Translate that provider-side parse failure into the backend
            # contract so LLMClient can apply its bounded retry and failure logging.
            # The SDK exception does not expose the complete raw response reliably.
            raise BackendError(
                f"model returned invalid {schema.__name__}: {exc}"
            ) from exc
        except self._anthropic.APIConnectionError as exc:
            raise BackendError(
                f"Anthropic request failed transiently ({type(exc).__name__})"
            ) from exc
        except self._anthropic.APIStatusError as exc:
            status = int(getattr(exc, "status_code", 0) or 0)
            response = getattr(exc, "response", None)
            raw = getattr(response, "text", "") if response is not None else ""
            retryable = status >= 500 or status == 408
            raise BackendError(
                f"Anthropic request failed (HTTP {status or 'unknown'}; "
                f"{type(exc).__name__})",
                raw=raw,
                retryable=retryable,
            ) from exc
        usage = getattr(response, "usage", None)
        if usage is not None:
            self.last_usage = BackendUsage(
                input_tokens=int(getattr(usage, "input_tokens", 0) or 0),
                output_tokens=int(getattr(usage, "output_tokens", 0) or 0),
                cache_read_tokens=int(
                    getattr(usage, "cache_read_input_tokens", 0) or 0
                ),
                cache_write_tokens=int(
                    getattr(usage, "cache_creation_input_tokens", 0) or 0
                ),
            )
        parsed = response.parsed_output
        if parsed is None:  # refusal or unparsable — surface, don't guess
            raise BackendError(
                f"model returned no parsable {schema.__name__} "
                f"(stop_reason={response.stop_reason})"
            )
        return parsed.model_dump_json()


class OpenAICompatibleBackend:
    """Backend for OpenAI-compatible `/v1/chat/completions` endpoints.

    The endpoint and authentication environment variable are configurable so the
    transport works with hosted providers and unauthenticated local gateways. The
    response-format mode is configurable because compatible servers implement
    different subsets of JSON Schema structured output.
    """

    def __init__(self, config: Config | None = None, client: httpx.Client | None = None):
        self._config = config or get_config()
        self._client = client or httpx.Client(timeout=self._config.llm.timeout_seconds)
        # The compatible transport does not currently send a seed because support is not
        # portable across endpoints. Convergence output must disclose this as unavailable.
        self.sampling_seed: int | None = None
        self.last_usage: BackendUsage | None = None
        self.tracks_usage = True

    def complete(self, *, system: str, user: str, schema: type[BaseModel], context: dict) -> str:
        self.last_usage = None
        llm = self._config.llm
        schema_json = schema.model_json_schema()
        schema_instruction = (
            f"\n\nReturn only valid JSON matching this JSON Schema:\n{schema_json}"
        )
        payload: dict = {
            "model": self._config.model.name,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user + schema_instruction},
            ],
            "max_tokens": self._config.model.max_tokens,
            "temperature": self._config.model.temperature,
        }
        if llm.response_format == "json_schema":
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": schema.__name__,
                    # The shared client performs authoritative Pydantic validation.
                    # Non-strict server-side schema handling supports a wider range of
                    # compatible gateways and schemas containing optional/default fields.
                    "strict": False,
                    "schema": schema_json,
                },
            }
        elif llm.response_format == "json_object":
            payload["response_format"] = {"type": "json_object"}

        headers = {"Content-Type": "application/json"}
        api_key = os.environ.get(llm.api_key_env) if llm.api_key_env else None
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        url = f"{llm.base_url.rstrip('/')}/chat/completions"
        try:
            response = self._client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            body = response.json()
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            raise BackendError(
                f"OpenAI-compatible request failed (HTTP {status})",
                raw=exc.response.text,
                retryable=status >= 500 or status == 408,
            ) from exc
        except httpx.RequestError as exc:
            raise BackendError(
                f"OpenAI-compatible request failed transiently ({type(exc).__name__})"
            ) from exc
        except ValueError as exc:
            raw = getattr(locals().get("response"), "text", "")
            raise BackendError(
                "OpenAI-compatible response was not valid JSON", raw=raw
            ) from exc

        try:
            choice = body["choices"][0]
            message = choice["message"]
            content = message.get("content")
        except (KeyError, IndexError, TypeError) as exc:
            raise BackendError(
                "OpenAI-compatible response had no completion choice", raw=str(body)
            ) from exc
        if not isinstance(content, str) or not content.strip():
            refusal = message.get("refusal") if isinstance(message, dict) else None
            raise BackendError(
                f"OpenAI-compatible model returned no content"
                + (f": {refusal}" if refusal else ""),
                raw=str(body),
            )
        usage = body.get("usage")
        if isinstance(usage, dict):
            details = usage.get("prompt_tokens_details")
            cached = details.get("cached_tokens", 0) if isinstance(details, dict) else 0
            prompt_tokens = int(usage.get("prompt_tokens", 0) or 0)
            cached_tokens = int(cached or 0)
            self.last_usage = BackendUsage(
                # OpenAI-compatible APIs commonly include cached tokens in
                # prompt_tokens. Store the non-cached remainder so aggregate
                # processed tokens do not double-count cache reads.
                input_tokens=max(0, prompt_tokens - cached_tokens),
                output_tokens=int(usage.get("completion_tokens", 0) or 0),
                cache_read_tokens=cached_tokens,
            )
        return content


# A scripted handler receives the same call a stage made and returns either a model
# instance (serialized for the client to re-validate) or a raw string.
ScriptedHandler = Callable[[str, str, type[BaseModel], dict], "BaseModel | str"]


class ScriptedBackend:
    """Deterministic backend for tests. Delegates to a handler; no network.

    Because the pipeline is deterministic given a fixture, the handler routes on the
    structured `context` (stage/lens/repo_id/…). Returning a raw string that is not
    valid for the schema drives the client's retry / ValidationFailure path.
    """

    def __init__(self, handler: ScriptedHandler):
        self._handler = handler
        self.calls: list[dict] = []
        self.sampling_seed: int | None = 0
        self.last_usage: BackendUsage | None = None
        self.tracks_usage = False

    def complete(self, *, system: str, user: str, schema: type[BaseModel], context: dict) -> str:
        self.calls.append({"schema": schema.__name__, "context": context})
        out = self._handler(system, user, schema, context)
        if isinstance(out, BaseModel):
            return out.model_dump_json()
        return str(out)
