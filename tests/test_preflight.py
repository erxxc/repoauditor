"""CLI startup preflight: database bootstrap, dependencies, tools, and credentials."""

from __future__ import annotations

from repoauditor.llm import LLMClient, ScriptedBackend
from repoauditor.preflight import check_model, check_runtime
from repoauditor.store import db


def test_preflight_initializes_database_and_warns_for_optional_tools(
    tmp_config, monkeypatch
):
    cfg = tmp_config.model_copy(update={
        "llm": tmp_config.llm.model_copy(update={
            "provider": "openai-compatible", "api_key_env": "",
        }),
    })
    monkeypatch.setattr("repoauditor.preflight.importlib.util.find_spec", lambda module: object())
    monkeypatch.setattr("repoauditor.preflight.shutil.which", lambda executable: None)

    result = check_runtime(cfg)

    assert result.ready is True
    assert result.migrations
    assert result.git_available is False
    assert result.missing_scanners == ["semgrep", "gitleaks", "pip-audit", "osv-scanner"]
    assert db.init_db(cfg) == []


def test_preflight_blocks_on_required_package_and_credential(tmp_config, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(
        "repoauditor.preflight.importlib.util.find_spec",
        lambda module: None if module == "anthropic" else object(),
    )
    monkeypatch.setattr("repoauditor.preflight.shutil.which", lambda executable: "/bin/tool")

    result = check_runtime(tmp_config)

    assert result.ready is False
    assert result.missing_packages == ["anthropic"]
    assert result.credential_error == "ANTHROPIC_API_KEY is not set"


def test_model_check_uses_shared_validation_path_for_anthropic_config(tmp_config):
    seen = {}

    def handler(system, user, schema, context):
        seen.update(schema=schema.__name__, context=context)
        return '{"status":"ready"}'

    result = check_model(tmp_config, LLMClient(ScriptedBackend(handler), tmp_config))

    assert result.ready is True
    assert result.provider == "anthropic"
    assert seen == {"schema": "_ModelProbe", "context": {"stage": "doctor", "check": "model"}}


def test_model_check_supports_openai_compatible_modes(tmp_config):
    for response_format in ("json_schema", "json_object", "none"):
        cfg = tmp_config.model_copy(update={
            "llm": tmp_config.llm.model_copy(update={
                "provider": "openai-compatible",
                "response_format": response_format,
            }),
        })
        client = LLMClient(
            ScriptedBackend(lambda system, user, schema, context: '{"status":"ready"}'),
            cfg,
        )

        result = check_model(cfg, client)

        assert result.ready is True
        assert result.provider == "openai-compatible"
        assert result.response_format == response_format


def test_model_check_returns_validation_failure(tmp_config):
    db.init_db(tmp_config)
    client = LLMClient(
        ScriptedBackend(lambda system, user, schema, context: '{"status":"wrong"}'),
        tmp_config,
    )

    result = check_model(tmp_config, client)

    assert result.ready is False
    assert "LLMValidationError" in (result.error or "")
