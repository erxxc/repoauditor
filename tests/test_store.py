"""Tests for the store layer — the only module that touches SQLite."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from repoauditor.store import db
from repoauditor.store.models import (
    Corroboration,
    Finding,
    Severity,
    SourceType,
    TrustBoundary,
)


def test_init_db_is_idempotent(tmp_config):
    applied_first = db.init_db(tmp_config)
    assert "0001_initial.sql" in applied_first
    applied_second = db.init_db(tmp_config)
    assert applied_second == []  # nothing to re-apply


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
