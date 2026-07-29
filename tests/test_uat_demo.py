"""Regression tests for the one-command UAT demo and its independent scorecard."""

from __future__ import annotations

import json
from types import SimpleNamespace

from typer.testing import CliRunner

from repoauditor import cli
from repoauditor.config import REPO_ROOT
from repoauditor.llm import remaining_pipeline_call_capacity
from repoauditor.store import db
from repoauditor.store.models import (
    Entity, EntityKind, FalsificationStatus, Finding,
)
from repoauditor.uat import score_demo


runner = CliRunner()


def _finding(cfg, file, status, *, line=10, tool="semgrep", lens=None):
    return db.insert_finding(Finding(
        repo_id="uat_lightweight_app", title=f"fixture case in {file}", file=file,
        line_start=line, line_end=line, citation_snippet="planted evidence",
        source_tool=None if lens else tool, source_lens=lens, confidence=0.9,
        severity="high", falsification_status=status, description="UAT case",
    ), cfg)


def test_scorecard_covers_all_ten_behaviors(tmp_config, tmp_path):
    db.init_db(tmp_config)
    confirmed_files = [
        "storefront/catalog.py", "storefront/integrations.py", "storefront/orders.py",
        "requirements.txt",
    ]
    for file in confirmed_files:
        _finding(tmp_config, file, FalsificationStatus.CONFIRMED)
    _finding(
        tmp_config, "storefront/config.py", FalsificationStatus.KILLED,
        line=24, tool="gitleaks",
    )
    _finding(
        tmp_config, "storefront/config.py", FalsificationStatus.KILLED,
        line=24, tool=None, lens="owasp",
    )
    _finding(tmp_config, "storefront/invoices.py", FalsificationStatus.KILLED)
    _finding(tmp_config, "storefront/legacy.py", FalsificationStatus.KILLED)
    _finding(tmp_config, "storefront/account.py", FalsificationStatus.KILLED)
    db.insert_entity(Entity(
        repo_id="uat_lightweight_app", kind=EntityKind.DATA_STORE,
        name="customers PII store", location="storefront/db.py",
    ), tmp_config)

    scorecard = score_demo(
        "uat_lightweight_app",
        REPO_ROOT / "tests/fixtures/uat_lightweight_app/expected_findings.json",
        tmp_config,
        out_dir=tmp_path / "score",
    )
    assert (scorecard.passed, scorecard.total) == (10, 10)
    assert "10/10" in scorecard.markdown_path.read_text()
    assert json.loads(scorecard.json_path.read_text())["passed"] == 10


def test_scorecard_separates_safe_negative_outcome_from_mechanism_coverage(
    tmp_config, tmp_path,
):
    db.init_db(tmp_config)

    scorecard = score_demo(
        "uat_lightweight_app",
        REPO_ROOT / "tests/fixtures/uat_lightweight_app/expected_findings.json",
        tmp_config,
        out_dir=tmp_path / "score",
    )

    negative = {case.case: case for case in scorecard.cases if case.case in {4, 7, 8, 9, 10}}
    assert all(case.passed for case in negative.values())
    assert all(not case.mechanism_exercised for case in negative.values())
    assert all(case.coverage == "not-exercised" for case in negative.values())
    text = scorecard.markdown_path.read_text()
    assert "Whether detection raised it" in text
    assert "not exercised" in text


def test_demo_missing_key_message_is_explicit(tmp_config, monkeypatch):
    cfg = tmp_config.model_copy(update={"root": REPO_ROOT})
    monkeypatch.setattr(cli, "get_config", lambda: cfg)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    result = runner.invoke(cli.app, ["demo"])

    assert result.exit_code == 1
    assert "Demo cannot start: no API key present" in result.output
    assert 'export ANTHROPIC_API_KEY="your-key-here"' in result.output
    assert "never written to the repository" in result.output


def test_demo_executes_inside_a_durable_usage_budget_scope(tmp_config, monkeypatch):
    cfg = tmp_config.model_copy(update={
        "root": REPO_ROOT,
        "llm": tmp_config.llm.model_copy(update={
            "max_calls_per_pipeline_run": 7,
            "max_tokens_per_pipeline_run": 1000,
        }),
    })
    monkeypatch.setattr(cli, "get_config", lambda: cfg)
    monkeypatch.setattr(cli, "_preflight", lambda config: cli.PreflightResult())
    observed = {}

    def execute(config, snapshot, expectations, trials, seed, non_interactive):
        observed["remaining"] = remaining_pipeline_call_capacity(config)
        return [str(snapshot)], SimpleNamespace(
            repo_id="uat_lightweight_app", commit="fixture-commit"
        )

    monkeypatch.setattr(cli, "_execute_demo", execute)
    result = runner.invoke(cli.app, ["demo", "--non-interactive"])

    assert result.exit_code == 0, result.output
    assert observed["remaining"] == 7
    pipeline = db.list_pipeline_runs(cfg, repo_id="uat_lightweight_app")[0]
    assert pipeline.status.value == "completed"
    assert pipeline.commit_hash == "fixture-commit"


def test_demo_continue_uses_artifact_path_without_repeating_pipeline(
    tmp_config, monkeypatch,
):
    cfg = tmp_config.model_copy(update={"root": REPO_ROOT})
    monkeypatch.setattr(cli, "get_config", lambda: cfg)
    monkeypatch.setattr(cli, "_preflight", lambda config: cli.PreflightResult())
    observed = {}

    def continue_demo(config, expectations, trials, seed, non_interactive):
        observed.update({
            "expectations": expectations.name,
            "trials": trials,
            "seed": seed,
            "non_interactive": non_interactive,
        })
        return [], SimpleNamespace(
            repo_id="uat_lightweight_app", commit="existing-commit"
        )

    monkeypatch.setattr(cli, "_continue_demo", continue_demo)
    monkeypatch.setattr(
        cli, "_execute_demo",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("full demo pipeline must not repeat")
        ),
    )

    result = runner.invoke(
        cli.app,
        ["demo", "--continue", "--trials", "123", "--seed", "7", "--non-interactive"],
    )

    assert result.exit_code == 0, result.output
    assert observed == {
        "expectations": "expected_findings.json",
        "trials": 123,
        "seed": 7,
        "non_interactive": True,
    }
