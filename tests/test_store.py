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
