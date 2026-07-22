"""End-to-end CLI tests — the report projections and the review checkpoint commands driven
through the actual typer app, so the "full CLI run no longer dies at report" milestone and
the review list/decide surface are exercised exactly as a user would.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from repoauditor import cli
from repoauditor.config import load_deal_risk, load_priors
from repoauditor.review import raise_review_requests
from repoauditor.store import db
from repoauditor.store.models import (
    FalsificationStatus,
    Finding,
    TriageLabelSource,
    TrustBoundary,
)

runner = CliRunner()


@pytest.fixture
def wired(tmp_config, monkeypatch):
    """A populated store + `cli.get_config` pointed at it, so the app hits the tmp DB."""
    cfg = tmp_config.model_copy(update={
        "priors": load_priors(), "deal_risk": load_deal_risk(),
    })
    monkeypatch.setattr(cli, "get_config", lambda: cfg)
    db.init_db(cfg)
    tb = db.insert_trust_boundary(
        TrustBoundary(repo_id="r", name="public HTTP edge", description="customer traffic"), cfg)
    db.insert_finding(Finding(
        repo_id="r", title="SQL injection", file="app.py", line_start=24, line_end=24,
        citation_snippet="SELECT * FROM users WHERE id = ' + user_id",
        source_lens="owasp", confidence=0.9, severity="critical",
        falsification_status=FalsificationStatus.CONFIRMED, description="sqli [CWE-89]",
        trust_boundary_id=tb), cfg)
    held = db.insert_finding(Finding(
        repo_id="r", title="Ambiguous input", file="app.py", line_start=22, line_end=22,
        citation_snippet="request.args.get('id')", source_lens="owasp", confidence=0.6,
        severity="low", falsification_status=FalsificationStatus.UNRESOLVED,
        description="[CWE-20]", trust_boundary_id=tb), cfg)
    raise_review_requests("r", cfg)   # opens a review request for the unresolved finding
    return cfg, held


def test_report_engineering_cli(wired):
    result = runner.invoke(cli.app, ["report", "r", "--mode", "engineering"])
    assert result.exit_code == 0, result.output
    assert "Engineering Remediation Backlog" in result.stdout
    assert "SELECT * FROM users WHERE id = ' + user_id" in result.stdout  # citation preserved
    assert "Ambiguous input" not in result.stdout                          # held -> excluded


def test_report_memo_cli(wired):
    result = runner.invoke(cli.app, ["report", "r", "--mode", "memo"])
    assert result.exit_code == 0, result.output
    assert "Security Risk Memo" in result.stdout
    assert "Appendix: Quantitative Risk Model" in result.stdout
    assert "Ambiguous input" not in result.stdout


def test_report_memo_record_audit_cli(wired):
    cfg, _held = wired
    assert db.list_simulation_runs("r", cfg) == []
    result = runner.invoke(cli.app, ["report", "r", "--mode", "memo", "--record-audit"])
    assert result.exit_code == 0, result.output
    assert "Security Risk Memo" in result.stdout
    # The flag left the audit trail; a plain memo run would not have.
    assert len(db.list_simulation_runs("r", cfg)) == 1


def test_review_list_and_decide_cli(wired):
    cfg, held = wired
    request = db.get_review_request(held, cfg)

    listed = runner.invoke(cli.app, ["review", "list", "r"])
    assert listed.exit_code == 0, listed.output
    assert f"finding #{held}" in listed.stdout
    assert f"request #{request.id}" in listed.stdout

    decided = runner.invoke(cli.app, [
        "review", "decide", "r", str(request.id),
        "--decision", "confirm", "--rationale", "traced the sink; it is reachable",
        "--reviewer", "alice",
    ])
    assert decided.exit_code == 0, decided.output
    assert "recorded decision" in decided.stdout
    # The append-only decision is recorded and releases the finding from the queue.
    assert db.latest_review_decision(request.id, cfg).disposition.value == "confirm"
    assert "No open review requests" in runner.invoke(cli.app, ["review", "list", "r"]).stdout


def _sarif_one() -> str:
    return json.dumps({
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "semgrep", "rules": [
            {"id": "py.cmdi", "name": "Command Injection",
             "properties": {"tags": ["CWE-78"], "security-severity": "9.5"}}]}},
            "results": [{"ruleId": "py.cmdi", "level": "error",
                "message": {"text": "cmdi hit"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "svc/run.py"},
                    "region": {"startLine": 21, "endLine": 21,
                               "snippet": {"text": "os.system(x)"}}}}]}]}]})


@pytest.fixture
def triage_cfg(tmp_config, monkeypatch):
    cfg = tmp_config.model_copy(update={"priors": load_priors()})
    monkeypatch.setattr(cli, "get_config", lambda: cfg)
    db.init_db(cfg)
    return cfg


def test_triage_and_manual_label_cli(triage_cfg, tmp_path):
    cfg = triage_cfg
    sp = tmp_path / "scan.sarif"
    sp.write_text(_sarif_one())

    triaged = runner.invoke(cli.app, ["triage", "acme", "--sarif", str(sp)])
    assert triaged.exit_code == 0, triaged.output
    # Cold start: no real labels yet, synthetic teacher owns the whole training mass.
    assert "real=0" in triaged.stdout and "synthetic_share=100%" in triaged.stdout
    assert "eval_on=synthetic" in triaged.stdout

    fid = db.list_findings("acme", cfg)[0].id
    labelled = runner.invoke(cli.app, [
        "triage-label", str(fid), "--disposition", "true_positive", "--note", "reachable",
    ])
    assert labelled.exit_code == 0, labelled.output
    assert "true positive" in labelled.stdout and "precedence" in labelled.stdout

    labels = db.list_triage_labels(config=cfg)
    assert len(labels) == 1
    assert labels[0].actionable is True
    assert labels[0].source is TriageLabelSource.MANUAL


def test_triage_label_cli_rejects_untriaged_finding(triage_cfg):
    result = runner.invoke(cli.app, [
        "triage-label", "999", "--disposition", "false_positive",
    ])
    assert result.exit_code == 1
    assert "no finding with id 999" in result.output


def test_review_decide_rejects_wrong_repo(wired):
    cfg, held = wired
    request = db.get_review_request(held, cfg)
    result = runner.invoke(cli.app, [
        "review", "decide", "WRONG", str(request.id),
        "--decision", "dismiss", "--rationale", "n/a",
    ])
    assert result.exit_code == 1
    assert "belongs to repo" in result.output
