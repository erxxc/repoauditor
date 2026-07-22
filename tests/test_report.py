"""Tests for the report projections — engineering backlog + deal-facing memo.

Both read `list_countable_findings` (deduped + review-gated). The backlog must carry every
citation through (no finding without a citation); the memo must rank by deal_risk_weight (not
technical severity), attach the FAIR appendix, and exclude anything blocked at review.
"""

from __future__ import annotations

import pytest

from repoauditor.config import load_deal_risk, load_priors
from repoauditor.report import build_backlog, build_memo
from repoauditor.review import raise_review_requests
from repoauditor.store import db
from repoauditor.store.models import FalsificationStatus, Finding, TrustBoundary


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
