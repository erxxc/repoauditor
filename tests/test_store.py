"""Tests for the store layer — the only module that touches SQLite."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from repoauditor.store import db
from repoauditor.store.models import (
    Corroboration,
    Finding,
    ReviewDecision,
    ReviewDisposition,
    ReviewRequest,
    Severity,
    SourceType,
    TrustBoundary,
)


def test_init_db_is_idempotent(tmp_config):
    applied_first = db.init_db(tmp_config)
    assert "0001_initial.sql" in applied_first
    applied_second = db.init_db(tmp_config)
    assert applied_second == []  # nothing to re-apply


def test_pre_methodology_database_migrates_without_losing_audit_data(
    tmp_config, monkeypatch,
):
    """Exercise the real 0001..0010 -> 0011/0012 upgrade, including legacy defaults."""
    all_migrations = db._discover_migrations()
    monkeypatch.setattr(
        db, "_discover_migrations", lambda: [item for item in all_migrations if item[0] <= 10]
    )
    db.init_db(tmp_config)

    finding_id = _f(tmp_config, tool="semgrep", status="confirmed")
    request_id = db.upsert_review_request(ReviewRequest(
        repo_id="r", finding_id=finding_id, stage="falsify",
        reason="legacy review", evidence={"trace": ["kept"]},
    ), tmp_config)
    decision_id = db.insert_review_decision(ReviewDecision(
        review_request_id=request_id, disposition=ReviewDisposition.CONFIRM,
        reviewer="uat", rationale="legacy decision remains auditable",
    ), tmp_config)
    # Seed the exact pre-0011 risk shape. The connection still comes from store/, which
    # remains the sole owner of SQLite setup and access.
    conn = db.get_connection(tmp_config)
    try:
        with conn:
            conn.execute(
                "INSERT INTO risk_scenario "
                "(repo_id, name, finding_ids, frequency_lambda, magnitude_mu, "
                "magnitude_sigma, frequency_source, magnitude_source, p_actionable) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("r", "data_breach", f"[{finding_id}]", 0.25, 10.0, 1.0,
                 "legacy.frequency", "legacy.magnitude", 0.8),
            )
    finally:
        conn.close()

    monkeypatch.setattr(db, "_discover_migrations", lambda: all_migrations)
    applied = db.init_db(tmp_config)
    assert applied == [
        "0011_risk_methodology.sql", "0012_scenario_inputs.sql",
        "0013_scenario_run_link.sql",
    ]

    assert db.list_findings("r", tmp_config)[0].id == finding_id
    assert db.list_review_requests("r", tmp_config)[0].evidence == {"trace": ["kept"]}
    assert db.list_review_decisions(request_id, tmp_config)[0].id == decision_id
    legacy = db.list_risk_scenarios("r", tmp_config)[0]
    assert legacy.validity_probabilities == []
    assert legacy.exposure_factors == []
    assert legacy.control_strengths == []
    assert legacy.loss_scale == 1.0
    assert legacy.simulation_run_id is None


def _f(cfg, *, lens=None, tool=None, sev="high", conf=0.8, desc="", file="app.py",
       start=24, end=24, status=None):
    from repoauditor.store.models import FalsificationStatus
    return db.insert_finding(Finding(
        repo_id="r", title="issue", file=file, line_start=start, line_end=end,
        citation_snippet="code", source_lens=lens, source_tool=tool, confidence=conf,
        severity=sev, description=desc,
        falsification_status=status or FalsificationStatus.UNRESOLVED,
    ), cfg)


def test_list_countable_findings_collapses_a_merged_group_but_keeps_rows_visible(tmp_config):
    """A corroborated issue (2 sources, same location) counts once — but neither row is
    deleted: the raw `list_findings` still returns both. Counting view, not a soft-delete."""
    from repoauditor.store.models import FalsificationStatus

    db.init_db(tmp_config)
    rep = _f(tmp_config, lens="owasp", conf=0.9, start=24, end=24)      # representative
    dup = _f(tmp_config, tool="sast", conf=0.6, start=24, end=24)       # same issue -> merged
    other = _f(tmp_config, lens="owasp", conf=0.8, file="other.py", start=5, end=5)
    killed = _f(tmp_config, tool="secrets", start=99, end=99,
                status=FalsificationStatus.KILLED)

    countable = {f.id for f in db.list_countable_findings("r", tmp_config)}
    assert countable == {rep, other}          # dup merged into rep; killed gated out
    assert dup not in countable

    # Nothing was removed — every row is still visible via the raw read.
    assert {f.id for f in db.list_findings("r", tmp_config)} == {rep, dup, other, killed}


def test_finding_round_trip_with_corroboration(tmp_config):
    db.init_db(tmp_config)
    tb_id = db.insert_trust_boundary(
        TrustBoundary(repo_id="r", name="public HTTP edge"), tmp_config
    )
    finding = Finding(
        repo_id="r",
        title="SQL injection",
        file="app.py",
        line_start=24,
        line_end=25,
        citation_snippet="SELECT * FROM users WHERE id = " + "user_id",
        source_lens="owasp",
        confidence=0.92,
        severity=Severity.CRITICAL,
        trust_boundary_id=tb_id,
        corroborated_by=[
            Corroboration(source_type=SourceType.TOOL, source_name="sast"),
        ],
    )
    finding_id = db.insert_finding(finding, tmp_config)
    assert finding_id > 0

    stored = db.list_findings("r", tmp_config)
    assert len(stored) == 1
    got = stored[0]
    assert got.title == "SQL injection"
    assert got.severity is Severity.CRITICAL
    assert got.trust_boundary_id == tb_id
    assert len(got.corroborated_by) == 1
    assert got.corroborated_by[0].source_name == "sast"


def test_finding_requires_a_source():
    with pytest.raises(ValidationError):
        Finding(
            repo_id="r", title="x", file="a.py", line_start=1, line_end=1,
            citation_snippet="...", confidence=0.5, severity=Severity.LOW,
        )
