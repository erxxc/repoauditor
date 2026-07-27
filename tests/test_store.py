"""Tests for the store layer — the only module that touches SQLite."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from repoauditor.store import db
from repoauditor.store.models import (
    Corroboration,
    Finding,
    IngestedRepo,
    ReviewDecision,
    ReviewDisposition,
    ReviewRequest,
    Severity,
    SourceType,
    TriageFeatureRecord,
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
        "0013_scenario_run_link.sql", "0014_triage_score_provenance.sql",
        "0015_triage_score_history.sql",
        "0016_triage_assessment.sql",
        "0017_triage_disposition.sql",
        "0018_security_claims.sql",
        "0019_structural_claim_verification.sql",
        "0020_model_usage.sql",
        "0021_finding_identity.sql",
        "0022_pipeline_run_parent.sql",
        "0023_claim_entry_evidence.sql",
        "0024_triage_cohort_metadata.sql",
        "0025_claim_caller_evidence.sql",
        "0026_claim_authorization_evidence.sql",
        "0027_claim_registration_evidence.sql",
        "0028_claim_language.sql",
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


def test_structural_status_migration_preserves_claim_audit_data(
    tmp_config, monkeypatch,
):
    """The terminology migration must retain legacy certificates and checks."""
    all_migrations = db._discover_migrations()
    monkeypatch.setattr(
        db, "_discover_migrations", lambda: [item for item in all_migrations if item[0] <= 18]
    )
    db.init_db(tmp_config)
    finding_id = _f(tmp_config, tool="semgrep")
    conn = db.get_connection(tmp_config)
    try:
        with conn:
            claim_id = conn.execute(
                "INSERT INTO security_claim "
                "(finding_id, claim_version, mechanism, source_evidence, path_nodes, "
                "path_predicates, producer_type, producer_name) "
                "VALUES (?, 'legacy-v1', 'sql_injection', '[]', '[]', '[]', "
                "'deterministic', 'legacy-slicer')",
                (finding_id,),
            ).lastrowid
            conn.execute(
                "INSERT INTO claim_verification "
                "(claim_id, status, verifier_name, verifier_version, checks, reason) "
                "VALUES (?, 'verified', 'legacy-checker', 'v1', "
                "'{\"source_present\": true}', 'legacy structural result')",
                (claim_id,),
            )
    finally:
        conn.close()

    monkeypatch.setattr(db, "_discover_migrations", lambda: all_migrations)
    assert db.init_db(tmp_config) == [
        "0019_structural_claim_verification.sql",
        "0020_model_usage.sql",
        "0021_finding_identity.sql",
        "0022_pipeline_run_parent.sql",
        "0023_claim_entry_evidence.sql",
        "0024_triage_cohort_metadata.sql",
        "0025_claim_caller_evidence.sql",
        "0026_claim_authorization_evidence.sql",
        "0027_claim_registration_evidence.sql",
        "0028_claim_language.sql",
    ]

    claim = db.list_security_claims(finding_id, tmp_config)[0]
    verification = db.list_claim_verifications(claim.id, tmp_config)[0]
    assert claim.snapshot_commit is None
    assert claim.entry_evidence == []
    assert claim.caller_evidence == []
    assert claim.authorization_evidence == []
    assert claim.registration_evidence == []
    assert claim.language == "python"
    assert verification.status.value == "verification_incomplete"
    assert verification.checks == {"source_present": True}
    assert verification.reason == "legacy structural result"


def test_triage_feature_cohort_metadata_round_trip_and_legacy_defaults(tmp_config):
    db.init_db(tmp_config)
    finding_id = _f(tmp_config, tool="semgrep")
    db.upsert_triage_features(TriageFeatureRecord(
        finding_id=finding_id,
        engagement="repo",
        rule_id="python.sql",
        fingerprint="fingerprint",
        features=[1.0],
        feature_names=["signal"],
        detector="semgrep",
        detector_source="sarif:run.tool.driver.name",
        language="python",
        language_source="sarif:artifact.sourceLanguage",
    ), tmp_config)

    stored = db.get_triage_features(finding_id, tmp_config)
    assert stored is not None
    assert stored.detector == "semgrep"
    assert stored.detector_source == "sarif:run.tool.driver.name"
    assert stored.language == "python"
    assert stored.language_source == "sarif:artifact.sourceLanguage"


def test_latest_ingested_repo_is_scoped_by_repo_id_and_newest_snapshot(tmp_config):
    db.init_db(tmp_config)
    db.record_ingested_repo(
        IngestedRepo(repo_id="acme", source="/src/acme", commit_hash="old"), tmp_config
    )
    db.record_ingested_repo(
        IngestedRepo(repo_id="other", source="/src/other", commit_hash="other"), tmp_config
    )
    db.record_ingested_repo(
        IngestedRepo(repo_id="acme", source="/src/acme", commit_hash="new"), tmp_config
    )

    latest = db.get_latest_ingested_repo("acme", tmp_config)

    assert latest is not None
    assert latest.commit_hash == "new"
    assert db.get_latest_ingested_repo("missing", tmp_config) is None


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
