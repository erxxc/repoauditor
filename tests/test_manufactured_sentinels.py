"""Manufactured-solution controls for falsification instrument qualification."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from repoauditor import cli
from repoauditor.eval.sentinels import (
    evaluate_manufactured_sentinels,
    load_sentinel_fixture,
)
from repoauditor.falsify.outcome import FalsificationOutcome, SelfCritique
from repoauditor.llm import LLMClient, ScriptedBackend
from repoauditor.store import db
from repoauditor.store.models import FalsificationStatus

FIXTURE = Path(__file__).parent / "fixtures" / "manufactured_sentinels"
WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "live-tests.yml"


def _instrument_handler(_system, user, schema, _context):
    if schema is SelfCritique:
        return SelfCritique(
            upholds=True, concern="manufactured scripted critique", confidence=0.99
        )
    negative = (
        '"SELECT * FROM products WHERE name LIKE ?"' in user
        or "_ALLOWED_PREVIEWS.get(page)" in user
    )
    return FalsificationOutcome(
        status=FalsificationStatus.KILLED if negative else FalsificationStatus.CONFIRMED,
        rationale="manufactured scripted verdict",
        reachable=not negative,
        mitigating_control="parameterization or allowlist" if negative else None,
        confidence=0.99,
    )


def _evaluate(tmp_config, handler=_instrument_handler):
    db.init_db(tmp_config)
    return evaluate_manufactured_sentinels(
        FIXTURE,
        config=tmp_config,
        llm=LLMClient(ScriptedBackend(handler), tmp_config),
    )


def test_balanced_sentinels_recover_known_positive_and_negative_answers(tmp_config):
    result = _evaluate(tmp_config)

    assert result.qualified is True
    assert result.positive_recovery == 1.0
    assert result.negative_recovery == 1.0
    assert result.overall_recovery == 1.0
    assert len(result.observations) == 4
    assert result.evidence_scope == (
        "manufactured controls only; not real-world precision or recall"
    )
    assert db.list_findings(config=tmp_config) == []


def test_one_wrong_answer_fails_closed(tmp_config):
    def wrong_handler(system, user, schema, context):
        outcome = _instrument_handler(system, user, schema, context)
        if (
            schema is FalsificationOutcome
            and '"SELECT * FROM products WHERE name LIKE ?"' in user
        ):
            return outcome.model_copy(update={"status": FalsificationStatus.CONFIRMED})
        return outcome

    result = _evaluate(tmp_config, wrong_handler)

    assert result.qualified is False
    assert result.negative_recovery == 0.5
    assert result.overall_recovery == 0.75


def test_corrupted_citation_is_rejected_before_model_use(tmp_path):
    fixture = tmp_path / "sentinels"
    shutil.copytree(FIXTURE, fixture)
    manifest_path = fixture / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["cases"][0]["citation_snippet"] = "not present in source"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="citation is not present"):
        load_sentinel_fixture(fixture)


def test_answer_key_is_outside_scanned_snapshot():
    manifest, snapshot, _digest = load_sentinel_fixture(FIXTURE)

    assert manifest.kind == "manufactured_solution"
    assert not (snapshot / "manifest.json").exists()
    source = (snapshot / "app.py").read_text()
    assert "expected" not in source
    assert '@app.get("/products/unsafe-search")' in source
    assert '@app.get("/products/safe-search")' in source
    assert '@app.get("/preview/unsafe")' in source
    assert '@app.get("/preview/safe")' in source
    assert 'request.args.get("url")' in source
    assert '_ALLOWED_PREVIEWS.get(page)' in source
    assert "allow_redirects=False" in source


def test_live_workflow_defaults_manual_runs_to_sentinels_and_keeps_monthly_full_lane():
    workflow = WORKFLOW.read_text()

    assert "default: sentinels-only" in workflow
    assert "live-lightweight" in workflow
    assert "bounded-independent" in workflow
    assert "full-live" not in workflow
    assert 'cron: "17 6 * * 2"' in workflow
    assert 'cron: "47 6 1 * *"' in workflow
    assert "retrieval-diagnostic" in workflow
    assert "actions/cache/restore@v4" in workflow
    assert "Require a validated corpus cache" in workflow
    assert "Verify restored protected holdout before paid execution" in workflow
    assert "--require-materialized" in workflow
    assert "corpus-readiness.json" in workflow
    assert "REPOAUDITOR_UAT_RESULTS: live-corpus-results.json" in workflow
    assert "live-corpus-junit.xml" in workflow
    assert "Retain live corpus evidence" in workflow
    assert "Smoke-test restored Juice Shop retrieval" in workflow
    assert 'REPOAUDITOR_RETRIEVAL_TRACE_FILES: "1"' in workflow
    assert "success() &&" in workflow
    assert "hashFiles('manufactured-sentinels.json') != ''" in workflow
    assert "timeout-minutes: 30" in workflow
    assert "timeout-minutes: 22" in workflow
    assert "timeout --signal=TERM --kill-after=30s 20m" in workflow
    assert "-s -vv -x --junitxml=live-corpus-junit.xml" in workflow
    assert "uat_lightweight_app" in workflow
    assert (
        "independent_serialize_javascript_pre,independent_serialize_javascript_post"
        in workflow
    )


def test_qualification_cli_exits_nonzero_on_miss(tmp_config, monkeypatch):
    failed = _evaluate(
        tmp_config,
        lambda _system, _user, schema, _context: (
            SelfCritique(upholds=True, concern="scripted", confidence=1.0)
            if schema is SelfCritique
            else FalsificationOutcome(
                status=FalsificationStatus.UNRESOLVED,
                rationale="scripted miss",
                confidence=0.2,
            )
        ),
    )
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    monkeypatch.setattr(
        cli, "evaluate_manufactured_sentinels", lambda fixture, config: failed
    )

    result = CliRunner().invoke(cli.app, ["qualify-instrument", "--format", "json"])

    assert result.exit_code == 1
    assert json.loads(result.stdout)["qualified"] is False


@pytest.mark.live
@pytest.mark.instrument
def test_live_manufactured_sentinels_qualify_falsification_instrument(tmp_config):
    """Weekly paid control: failure disqualifies the instrument run, not the target."""
    result = evaluate_manufactured_sentinels(FIXTURE, config=tmp_config)

    assert result.qualified, result.model_dump_json(indent=2)
