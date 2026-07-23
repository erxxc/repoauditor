"""Tests for the report projections — engineering backlog + deal-facing memo.

Both read `list_countable_findings` (deduped + review-gated). The backlog must carry every
citation through (no finding without a citation); the memo must rank by deal_risk_weight (not
technical severity), attach the FAIR appendix, and exclude anything blocked at review.
"""

from __future__ import annotations

import pytest

from repoauditor.config import load_deal_risk, load_priors
from repoauditor.analyze import quantify_appendix
from repoauditor.report import build_backlog, build_memo, write_memo
from repoauditor.review import raise_review_requests
from repoauditor.store import db
from repoauditor.store.models import (
    Corroboration,
    FalsificationStatus,
    Finding,
    RunStatus,
    SourceType,
    TrustBoundary,
)


@pytest.fixture
def cfg(tmp_config):
    """tmp_config with the real priors + deal-risk taxonomy (memo needs both)."""
    return tmp_config.model_copy(update={
        "priors": load_priors(), "deal_risk": load_deal_risk(),
    })


def _tb(cfg, name="public HTTP edge", desc="customer traffic"):
    return db.insert_trust_boundary(
        TrustBoundary(repo_id="r", name=name, description=desc), cfg)


def _finding(cfg, *, title, sev, desc="", lens="owasp", tool=None, file="app.py",
             start=10, end=10, tb=None, snippet="CODE", conf=0.8,
             status=FalsificationStatus.CONFIRMED):
    return db.insert_finding(Finding(
        repo_id="r", title=title, file=file, line_start=start, line_end=end,
        citation_snippet=snippet, source_lens=None if tool else lens, source_tool=tool,
        confidence=conf, severity=sev, description=desc, falsification_status=status,
        trust_boundary_id=tb), cfg)


# --------------------------------------------------------------------------- #
# Engineering backlog
# --------------------------------------------------------------------------- #
def test_backlog_carries_citations_and_orders_by_severity(cfg):
    db.init_db(cfg)
    tb = _tb(cfg)
    _finding(cfg, title="SQL injection", sev="critical", desc="sqli [CWE-89]", tb=tb,
             start=24, end=24, snippet="SELECT * FROM users WHERE id = ' + user_id")
    _finding(cfg, title="Weak hash", sev="low", desc="md5 [CWE-327]", tb=tb,
             start=5, end=5, snippet="hashlib.md5(pw)")

    out = build_backlog("r", cfg)
    # Citations carried through verbatim — never summarized away.
    assert "SELECT * FROM users WHERE id = ' + user_id" in out
    assert "hashlib.md5(pw)" in out
    assert "`app.py:24`" in out                       # location with line range
    assert out.index("## CRITICAL") < out.index("## LOW")   # highest severity first


def test_backlog_dedupes_a_merged_group(cfg):
    db.init_db(cfg)
    tb = _tb(cfg)
    _finding(cfg, title="Hardcoded secret", sev="high", desc="[CWE-798]", lens="owasp",
             conf=0.9, start=16, end=16, snippet="TOKEN='sk_live_x'", tb=tb)
    _finding(cfg, title="Hardcoded secret", sev="high", desc="[CWE-798]", tool="secrets",
             conf=0.6, start=16, end=16, snippet="TOKEN='****'", tb=tb)  # same issue
    _finding(cfg, title="SQL injection", sev="critical", desc="[CWE-89]", start=24, end=24,
             snippet="q", tb=tb)

    out = build_backlog("r", cfg)
    assert out.count("### [finding #") == 2   # 2 distinct issues, the secret counted once


def test_backlog_empty(cfg):
    db.init_db(cfg)
    assert "No findings to triage" in build_backlog("r", cfg)


# --------------------------------------------------------------------------- #
# Deal-facing memo
# --------------------------------------------------------------------------- #
def test_memo_ranks_by_deal_weight_and_attaches_appendix(cfg):
    db.init_db(cfg)
    tb = _tb(cfg)
    _finding(cfg, title="SQL injection", sev="critical", desc="sqli [CWE-89]", tb=tb,
             start=1, end=1, snippet="q1")
    _finding(cfg, title="Weak hashing", sev="low", desc="md5 [CWE-327]", tb=tb,
             start=2, end=2, snippet="q2")

    memo = build_memo("r", cfg)
    # Ranked by deal-risk weight (SQLi outweighs weak-hash), not just severity.
    assert memo.index("SQL injection") < memo.index("Weak hashing")
    # The FAIR Monte-Carlo appendix and a methodology note are attached.
    assert "Appendix: Quantitative Risk Model" in memo
    assert "FAIR" in memo and "## Methodology & confidence" in memo
    assert "deal-risk" in memo.lower()


def test_memo_excludes_findings_blocked_at_review(cfg):
    db.init_db(cfg)
    tb = _tb(cfg)
    _finding(cfg, title="SQL injection", sev="critical", desc="[CWE-89]", tb=tb,
             start=1, end=1, snippet="q")
    _finding(cfg, title="AmbiguousXYZ", sev="high", desc="[CWE-20]", tb=tb,
             start=99, end=99, snippet="q2", status=FalsificationStatus.UNRESOLVED)
    raise_review_requests("r", cfg)   # opens a request for the unresolved finding

    memo = build_memo("r", cfg)
    assert "AmbiguousXYZ" not in memo   # held at review -> withheld from the memo
    assert "SQL injection" in memo
    assert "1 finding(s) withheld pending analyst review" in memo


def test_empty_memo_never_hides_pending_review(cfg):
    db.init_db(cfg)
    tb = _tb(cfg)
    _finding(cfg, title="Ambiguous only", sev="high", desc="[CWE-20]", tb=tb,
             status=FalsificationStatus.UNRESOLVED)
    raise_review_requests("r", cfg)

    memo = build_memo("r", cfg)

    assert "No material deal-relevant findings surfaced" in memo
    assert "1 finding(s) withheld pending analyst review" in memo


def test_memo_discloses_validation_basis(cfg):
    db.init_db(cfg)
    tb = _tb(cfg)
    falsified_id = _finding(
        cfg, title="SQL injection", sev="critical", desc="[CWE-89]", tb=tb, start=1
    )
    corroborated_id = _finding(
        cfg, title="Hardcoded secret", sev="high", desc="[CWE-798]", tb=tb, start=2
    )
    db.add_corroboration(
        Corroboration(
            finding_id=corroborated_id,
            source_type=SourceType.TOOL,
            source_name="gitleaks",
        ),
        cfg,
    )

    memo = build_memo("r", cfg)

    assert "confirmed by falsification" in memo
    assert "independently corroborated (gitleaks)" in memo
    assert falsified_id != corroborated_id


def test_memo_labels_shared_model_lenses_as_correlated_agreement(cfg):
    db.init_db(cfg)
    tb = _tb(cfg)
    finding_id = _finding(
        cfg, title="Access control", sev="high", desc="[CWE-862]", tb=tb, start=3
    )
    db.add_corroboration(
        Corroboration(
            finding_id=finding_id,
            source_type=SourceType.LENS,
            source_name="supply_chain",
        ),
        cfg,
    )

    memo = build_memo("r", cfg)

    assert "multi-lens agreement (shared model lineage) (supply_chain)" in memo


def test_memo_surfaces_recorded_run_provenance_and_triage_context(cfg):
    db.init_db(cfg)
    tb = _tb(cfg)
    _finding(cfg, title="SQL injection", sev="critical", desc="[CWE-89]", tb=tb)
    pipeline = db.start_pipeline_run("/source", cfg)
    db.update_pipeline_run_identity(pipeline.id, "r", "abc123", cfg)
    db.start_stage_run(pipeline.id, "detect", cfg)
    db.finish_stage_run(
        pipeline.id,
        "detect",
        RunStatus.COMPLETED,
        summary={
            "semgrep_status": "complete",
            "scanner_coverage": {"checked": True, "missing": ["osv-scanner"]},
            "llm": {
                "provider": "anthropic",
                "model": "test-model",
                "prompt_versions": {"owasp": "owasp_v1"},
            },
        },
        config=cfg,
    )
    db.start_stage_run(pipeline.id, "triage", cfg)
    db.finish_stage_run(
        pipeline.id,
        "triage",
        RunStatus.COMPLETED,
        summary={
            "real_labels": 12,
            "synthetic_share": 0.4,
            "synthetic_dropped": False,
            "suppressed": 3,
            "model": "xgboost",
            "evaluations": [{
                "model": "xgboost", "eval_on": "real", "brier": 0.12,
                "average_precision": 0.81, "n_eval": 10,
            }],
        },
        config=cfg,
    )
    db.finish_pipeline_run(pipeline.id, RunStatus.COMPLETED, config=cfg)

    memo = build_memo("r", cfg, record_audit=True)

    assert "Repository commit:** `abc123`" in memo
    assert "Simulation run:** #1" in memo and "seed=0" in memo
    assert "Analysis timestamp:** not recorded" not in memo
    assert "anthropic/test-model" in memo and "owasp=owasp_v1" in memo
    assert "unavailable: osv-scanner" in memo
    assert "Real labels:** 12" in memo and "Synthetic training share:** 40.0%" in memo
    assert "Evaluation basis:** real" in memo
    assert "Triage model:** xgboost" in memo and "Evaluation sample:** 10 finding(s)" in memo
    assert "Brier score:** 0.1200" in memo and "Average precision:** 0.8100" in memo
    assert "Suppressed findings:** 3" in memo


def test_memo_default_is_read_only_no_audit_trail(cfg):
    db.init_db(cfg)
    tb = _tb(cfg)
    _finding(cfg, title="SQL injection", sev="critical", desc="sqli [CWE-89]", tb=tb,
             start=1, end=1, snippet="q")
    build_memo("r", cfg)  # default record_audit=False
    # A default memo is a pure read projection: nothing is written to the store.
    assert db.list_simulation_runs("r", cfg) == []


def test_memo_record_audit_persists_a_simulation_run_without_mutating_findings(cfg):
    db.init_db(cfg)
    tb = _tb(cfg)
    _finding(cfg, title="SQL injection", sev="critical", desc="sqli [CWE-89]", tb=tb,
             start=1, end=1, snippet="q")
    before = {f.id: f.severity for f in db.list_findings("r", cfg)}

    memo = build_memo("r", cfg, record_audit=True)
    assert "Security Risk Memo" in memo

    # The audit trail is written: exactly one SimulationRun recording what the memo used.
    runs = db.list_simulation_runs("r", cfg)
    assert len(runs) == 1 and runs[0].repo_id == "r"
    # ...and it is purely additive — no finding or severity was mutated by generating it.
    after = {f.id: f.severity for f in db.list_findings("r", cfg)}
    assert after == before


def test_memo_reuses_quantification_without_second_simulation(cfg, monkeypatch):
    db.init_db(cfg)
    tb = _tb(cfg)
    _finding(cfg, title="SQL injection", sev="critical", desc="sqli [CWE-89]", tb=tb,
             start=1, end=1, snippet="q")

    quantification = quantify_appendix(
        "r", cfg, trials=1_234, seed=19, persist=True
    )
    # Any attempt by the memo to quantify again is a regression. Its audit row and
    # trial/seed settings must be exactly those produced above.
    monkeypatch.setattr(
        "repoauditor.report.memo.generate_appendix",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("simulated twice")),
    )

    paths = write_memo("r", cfg, record_audit=True, quantification=quantification)

    memo_path = next(path for path in paths if path.name == "memo.md")
    assert "1,234" in memo_path.read_text()
    assert {path.name for path in paths} >= {
        "memo.md", "risk_appendix.md", "loss_exceedance.png", "tornado.png"
    }
    runs = db.list_simulation_runs("r", cfg)
    assert len(runs) == 1
    assert runs[0].trials == 1_234 and runs[0].seed == 19


def test_memo_rejects_unrecorded_quantification_when_audit_is_required(cfg):
    db.init_db(cfg)
    quantification = quantify_appendix("r", cfg, trials=100, seed=3, persist=False)

    with pytest.raises(ValueError, match="persist=True"):
        build_memo("r", cfg, record_audit=True, quantification=quantification)
