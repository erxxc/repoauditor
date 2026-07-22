"""Tests for the shared LLM client — validation, bounded retry, confidence gating."""

from __future__ import annotations

import json

import httpx
import pytest
from pydantic import BaseModel

from repoauditor.detect.ensemble import LensCandidate, LensFindings, _resolve_confidence
from repoauditor.detect.retrieval import RetrievalIndex
from repoauditor.llm import (
    BackendError,
    LLMClient,
    LLMValidationError,
    OpenAICompatibleBackend,
    ScriptedBackend,
    get_llm_client,
)
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
            }}]},
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


def test_get_llm_client_selects_openai_compatible_backend(tmp_config):
    cfg = tmp_config.model_copy(update={
        "llm": tmp_config.llm.model_copy(update={"provider": "openai-compatible"}),
    })
    assert isinstance(get_llm_client(cfg)._backend, OpenAICompatibleBackend)


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
