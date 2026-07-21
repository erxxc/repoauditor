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

from typing import Callable, Protocol, runtime_checkable

from pydantic import BaseModel

from ..config import Config, get_config


class BackendError(RuntimeError):
    """The backend produced no usable response (refusal, empty output)."""

    def __init__(self, message: str, raw: str = ""):
        super().__init__(message)
        self.raw = raw


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
        self._client = anthropic.Anthropic()

    def complete(self, *, system: str, user: str, schema: type[BaseModel], context: dict) -> str:
        response = self._client.messages.parse(
            model=self._config.model.name,
            max_tokens=self._config.model.max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
            output_format=schema,
        )
        parsed = response.parsed_output
        if parsed is None:  # refusal or unparsable — surface, don't guess
            raise BackendError(
                f"model returned no parsable {schema.__name__} "
                f"(stop_reason={response.stop_reason})"
            )
        return parsed.model_dump_json()


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

    def complete(self, *, system: str, user: str, schema: type[BaseModel], context: dict) -> str:
        self.calls.append({"schema": schema.__name__, "context": context})
        out = self._handler(system, user, schema, context)
        if isinstance(out, BaseModel):
            return out.model_dump_json()
        return str(out)
