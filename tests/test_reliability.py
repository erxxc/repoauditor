"""Tests for the shared LLM client — validation, bounded retry, confidence gating."""

from __future__ import annotations

import json
from types import SimpleNamespace

import anthropic
import httpx
import pytest
from pydantic import BaseModel

from repoauditor.detect.ensemble import LensCandidate, LensFindings, _resolve_confidence
from repoauditor.detect.retrieval import RetrievalIndex
from repoauditor.llm import (
    AnthropicBackend,
    BackendError,
    LLMClient,
    LLMValidationError,
    OpenAICompatibleBackend,
    ScriptedBackend,
    get_llm_client,
    model_usage_scope,
)
from repoauditor.llm.backends import BackendUsage
from repoauditor.llm.client import LLMBudgetExceeded
from repoauditor.store import db


class _Demo(BaseModel):
    value: str
    confidence: float = 1.0


class _NoConfidence(BaseModel):
    x: int


def _client(handler, tmp_config) -> LLMClient:
    return LLMClient(ScriptedBackend(handler), tmp_config)


def _call(client, schema, module="testmod", prompt_version="p_v1"):
    return client.call(
        module=module, prompt_version=prompt_version,
        system="system", user="user", schema=schema,
    )


# --------------------------------------------------------------------------- #
# Validation + retry + ValidationFailure logging
# --------------------------------------------------------------------------- #
def test_exhausted_retries_log_validation_failure_and_raise(tmp_config):
    db.init_db(tmp_config)
    client = _client(lambda s, u, schema, ctx: "this is not valid json", tmp_config)

    with pytest.raises(LLMValidationError):
        _call(client, _Demo)

    failures = db.list_validation_failures(tmp_config)
    assert len(failures) == 1
    assert failures[0].module == "testmod"
    assert failures[0].prompt_version == "p_v1"
    assert failures[0].validation_error  # non-empty


def test_retry_then_success_logs_no_failure(tmp_config):
    db.init_db(tmp_config)
    attempts = {"n": 0}

    def handler(system, user, schema, ctx):
        attempts["n"] += 1
        if attempts["n"] == 1:
            return "garbage"  # first attempt fails validation
        return _Demo(value="ok")  # retry succeeds

    completion = _call(_client(handler, tmp_config), _Demo)

    assert completion.value.value == "ok"
    assert attempts["n"] == 2  # one retry was needed
    assert db.list_validation_failures(tmp_config) == []


# --------------------------------------------------------------------------- #
# Confidence gating
# --------------------------------------------------------------------------- #
def test_low_confidence_is_flagged(tmp_config):
    db.init_db(tmp_config)
    completion = _call(_client(lambda s, u, sc, c: _Demo(value="x", confidence=0.3), tmp_config), _Demo)
    assert completion.confidence == 0.3
    assert completion.low_confidence is True


def test_high_confidence_is_not_flagged(tmp_config):
    db.init_db(tmp_config)
    completion = _call(_client(lambda s, u, sc, c: _Demo(value="x", confidence=0.9), tmp_config), _Demo)
    assert completion.low_confidence is False


def test_model_without_confidence_field_is_never_flagged(tmp_config):
    db.init_db(tmp_config)
    completion = _call(_client(lambda s, u, sc, c: _NoConfidence(x=1), tmp_config), _NoConfidence)
    assert completion.confidence is None
    assert completion.low_confidence is False


# --------------------------------------------------------------------------- #
# OpenAI-compatible backend
# --------------------------------------------------------------------------- #
def test_openai_compatible_backend_posts_schema_and_returns_content(
    tmp_config, monkeypatch
):
    monkeypatch.setenv("TEST_OPENAI_KEY", "secret-token")
    cfg = tmp_config.model_copy(update={
        "model": tmp_config.model.model_copy(update={"name": "local-model"}),
        "llm": tmp_config.llm.model_copy(update={
            "provider": "openai-compatible",
            "base_url": "http://localhost:11434/v1/",
            "api_key_env": "TEST_OPENAI_KEY",
        }),
    })
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["authorization"] = request.headers.get("authorization")
        seen["payload"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={"choices": [{"message": {
                "role": "assistant",
                "content": '{"value":"ok","confidence":0.9}',
            }}], "usage": {
                "prompt_tokens": 120,
                "completion_tokens": 12,
                "prompt_tokens_details": {"cached_tokens": 20},
            }},
        )

    backend = OpenAICompatibleBackend(
        cfg, httpx.Client(transport=httpx.MockTransport(handler))
    )
    raw = backend.complete(system="sys", user="prompt", schema=_Demo, context={})

    assert _Demo.model_validate_json(raw).value == "ok"
    assert seen["url"] == "http://localhost:11434/v1/chat/completions"
    assert seen["authorization"] == "Bearer secret-token"
    assert seen["payload"]["model"] == "local-model"
    assert seen["payload"]["response_format"]["type"] == "json_schema"
    assert "JSON Schema" in seen["payload"]["messages"][1]["content"]
    assert backend.last_usage == BackendUsage(
        input_tokens=100, output_tokens=12, cache_read_tokens=20
    )


def test_openai_compatible_backend_supports_keyless_prompt_only_mode(tmp_config):
    cfg = tmp_config.model_copy(update={
        "llm": tmp_config.llm.model_copy(update={
            "provider": "openai-compatible",
            "base_url": "http://localhost:8000/v1",
            "api_key_env": "",
            "response_format": "none",
        }),
    })

    def handler(request: httpx.Request) -> httpx.Response:
        assert "authorization" not in request.headers
        assert "response_format" not in json.loads(request.content)
        return httpx.Response(
            200, json={"choices": [{"message": {"content": '{"x":1}'}}]}
        )

    backend = OpenAICompatibleBackend(
        cfg, httpx.Client(transport=httpx.MockTransport(handler))
    )
    assert backend.complete(system="s", user="u", schema=_NoConfidence, context={}) == '{"x":1}'


def test_openai_compatible_backend_surfaces_http_error(tmp_config):
    cfg = tmp_config.model_copy(update={
        "llm": tmp_config.llm.model_copy(update={"provider": "openai-compatible"}),
    })
    backend = OpenAICompatibleBackend(
        cfg,
        httpx.Client(transport=httpx.MockTransport(
            lambda request: httpx.Response(401, text="unauthorized")
        )),
    )
    with pytest.raises(BackendError, match="request failed") as exc:
        backend.complete(system="s", user="u", schema=_Demo, context={})
    assert exc.value.raw == "unauthorized"
    assert exc.value.retryable is False


def test_terminal_openai_error_is_not_retried_by_shared_client(tmp_config):
    db.init_db(tmp_config)
    attempts = {"n": 0}
    cfg = tmp_config.model_copy(update={
        "llm": tmp_config.llm.model_copy(update={"provider": "openai-compatible"}),
    })

    def handler(_request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        return httpx.Response(429, text="monthly quota exhausted")

    backend = OpenAICompatibleBackend(
        cfg, httpx.Client(transport=httpx.MockTransport(handler))
    )
    with pytest.raises(BackendError, match="HTTP 429"):
        _call(LLMClient(backend, cfg), _Demo)

    assert attempts["n"] == 1
    usage = db.list_model_usage(cfg)
    assert len(usage) == 1
    assert usage[0].usage_available is False


def test_transient_openai_error_uses_shared_bounded_retry(tmp_config):
    db.init_db(tmp_config)
    attempts = {"n": 0}
    cfg = tmp_config.model_copy(update={
        "llm": tmp_config.llm.model_copy(update={
            "provider": "openai-compatible", "max_retries": 1,
        }),
    })

    def handler(_request: httpx.Request) -> httpx.Response:
        attempts["n"] += 1
        if attempts["n"] == 1:
            return httpx.Response(503, text="temporarily unavailable")
        return httpx.Response(
            200, json={"choices": [{"message": {
                "content": '{"value":"ok","confidence":0.9}',
            }}]},
        )

    backend = OpenAICompatibleBackend(
        cfg, httpx.Client(transport=httpx.MockTransport(handler))
    )
    assert _call(LLMClient(backend, cfg), _Demo).value.value == "ok"
    assert attempts["n"] == 2


def test_get_llm_client_selects_openai_compatible_backend(tmp_config):
    cfg = tmp_config.model_copy(update={
        "llm": tmp_config.llm.model_copy(update={"provider": "openai-compatible"}),
    })
    assert isinstance(get_llm_client(cfg)._backend, OpenAICompatibleBackend)


# --------------------------------------------------------------------------- #
# Anthropic structured-output backend
# --------------------------------------------------------------------------- #
def test_anthropic_backend_uses_configured_timeout_and_no_hidden_retries(
    tmp_config, monkeypatch,
):
    seen = {}

    class FakeAnthropic:
        def __init__(self, **kwargs):
            seen.update(kwargs)

    monkeypatch.setattr(anthropic, "Anthropic", FakeAnthropic)
    cfg = tmp_config.model_copy(update={
        "llm": tmp_config.llm.model_copy(update={"timeout_seconds": 17.5}),
    })

    AnthropicBackend(cfg)

    assert seen["timeout"] == 17.5
    assert seen["max_retries"] == 0


def test_anthropic_backend_captures_provider_usage(tmp_config):
    response = SimpleNamespace(
        parsed_output=_Demo(value="ok"),
        stop_reason="end_turn",
        usage=SimpleNamespace(
            input_tokens=100,
            output_tokens=11,
            cache_read_input_tokens=30,
            cache_creation_input_tokens=7,
        ),
    )
    backend = object.__new__(AnthropicBackend)
    backend._config = tmp_config
    backend._client = SimpleNamespace(
        messages=SimpleNamespace(parse=lambda **_kwargs: response)
    )
    backend.last_usage = None

    assert _Demo.model_validate_json(
        backend.complete(system="s", user="u", schema=_Demo, context={})
    ).value == "ok"
    assert backend.last_usage == BackendUsage(
        input_tokens=100,
        output_tokens=11,
        cache_read_tokens=30,
        cache_write_tokens=7,
    )


@pytest.mark.parametrize(
    ("error_type", "status", "retryable"),
    [
        (anthropic.AuthenticationError, 401, False),
        (anthropic.RateLimitError, 429, False),
        (anthropic.InternalServerError, 500, True),
    ],
)
def test_anthropic_status_error_retry_classification(
    tmp_config, error_type, status, retryable,
):
    request = httpx.Request("POST", "https://api.anthropic.com/v1/messages")
    response = httpx.Response(status, request=request, text="provider detail")
    provider_error = error_type("request failed", response=response, body=None)

    class Messages:
        def parse(self, **_kwargs):
            raise provider_error

    backend = object.__new__(AnthropicBackend)
    backend._config = tmp_config
    backend._anthropic = anthropic
    backend._client = SimpleNamespace(messages=Messages())
    backend.last_usage = None

    with pytest.raises(BackendError, match=f"HTTP {status}") as exc:
        backend.complete(system="s", user="u", schema=_Demo, context={})
    assert exc.value.retryable is retryable
    assert exc.value.raw == "provider detail"


def test_anthropic_sdk_parse_failure_uses_shared_bounded_retry(tmp_config):
    db.init_db(tmp_config)
    attempts = {"n": 0}

    class Messages:
        def parse(self, **_kwargs):
            attempts["n"] += 1
            if attempts["n"] == 1:
                # Mirrors a provider response rejected inside messages.parse()
                # before AnthropicBackend receives a parsed response.
                return _Demo.model_validate_json('{"value": "broken",}')
            return type("Response", (), {
                "parsed_output": _Demo(value="ok"),
                "stop_reason": "end_turn",
            })()

    backend = object.__new__(AnthropicBackend)
    backend._config = tmp_config
    backend._client = type("Client", (), {"messages": Messages()})()
    backend.sampling_seed = None

    completion = _call(LLMClient(backend, tmp_config), _Demo)

    assert completion.value.value == "ok"
    assert attempts["n"] == 2
    assert db.list_validation_failures(tmp_config) == []


def test_usage_is_persisted_and_pipeline_call_budget_stops_before_next_request(tmp_config):
    db.init_db(tmp_config)
    cfg = tmp_config.model_copy(update={
        "llm": tmp_config.llm.model_copy(update={
            "max_calls_per_pipeline_run": 1,
            "max_tokens_per_pipeline_run": 0,
        }),
    })
    pipeline = db.start_pipeline_run("fixture", cfg)

    class UsageBackend:
        sampling_seed = None
        tracks_usage = True

        def __init__(self):
            self.calls = 0
            self.last_usage = None

        def complete(self, **_kwargs):
            self.calls += 1
            self.last_usage = BackendUsage(input_tokens=10, output_tokens=3)
            return _Demo(value="ok").model_dump_json()

    backend = UsageBackend()
    client = LLMClient(backend, cfg)
    with model_usage_scope(pipeline.id):
        assert _call(client, _Demo).value.value == "ok"
        with pytest.raises(LLMBudgetExceeded, match="1/1 provider calls"):
            _call(client, _Demo)

    assert backend.calls == 1
    usage = db.list_model_usage(cfg, pipeline_run_id=pipeline.id)
    assert len(usage) == 1
    assert usage[0].input_tokens == 10
    assert usage[0].output_tokens == 3
    assert usage[0].module == "testmod"


def test_failed_provider_attempt_counts_toward_call_budget_without_fabricated_tokens(
    tmp_config,
):
    db.init_db(tmp_config)
    cfg = tmp_config.model_copy(update={
        "llm": tmp_config.llm.model_copy(update={
            "max_calls_per_pipeline_run": 1,
            "max_tokens_per_pipeline_run": 10,
            "max_retries": 2,
        }),
    })
    pipeline = db.start_pipeline_run("fixture", cfg)

    class FailingBackend:
        sampling_seed = None
        tracks_usage = True
        last_usage = None
        calls = 0

        def complete(self, **_kwargs):
            self.calls += 1
            raise BackendError("provider rejected request")

    backend = FailingBackend()
    with model_usage_scope(pipeline.id):
        with pytest.raises(LLMBudgetExceeded, match="1/1 provider calls"):
            _call(LLMClient(backend, cfg), _Demo)

    assert backend.calls == 1
    totals = db.summarize_model_usage(pipeline.id, cfg)
    assert totals["calls"] == 1
    assert totals["unknown_usage_calls"] == 1
    assert totals["input_tokens"] == 0
    assert db.list_model_usage(cfg, pipeline_run_id=pipeline.id)[0].input_tokens is None


# --------------------------------------------------------------------------- #
# detect low-confidence re-score path
# --------------------------------------------------------------------------- #
def test_detect_rescore_upgrades_low_confidence_candidate(tmp_config, tmp_path):
    db.init_db(tmp_config)
    index = RetrievalIndex().build(tmp_path)  # empty index is fine
    low = LensCandidate(
        title="maybe", file="a.py", line_start=1, line_end=1,
        citation_snippet="dangerous(x)", severity="high", confidence=0.2,
    )

    def handler(system, user, schema, ctx):
        # On the broader-context re-score, return the same candidate at high confidence.
        return LensFindings(findings=[low.model_copy(update={"confidence": 0.9})])

    cand, still_low = _resolve_confidence(
        low, "owasp", "prompt", index, "r", _client(handler, tmp_config), threshold=0.5
    )
    assert cand.confidence == 0.9
    assert still_low is False
