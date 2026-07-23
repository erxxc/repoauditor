"""Structured claims retain evidence and narrowly scoped verification."""

from pathlib import Path

from repoauditor.detect.retrieval import RetrievalIndex
from repoauditor.falsify.claims import claim_from_slice, verify_structural_claim
from repoauditor.falsify.slicing import build_python_slice
from repoauditor.store import db
from repoauditor.store.models import ClaimVerificationStatus, Finding

UAT = Path(__file__).parent / "fixtures" / "uat_lightweight_app" / "snapshot"


def _finding() -> Finding:
    return Finding(
        repo_id="r",
        title="SQL injection [CWE-89]",
        file="storefront/catalog.py",
        line_start=38,
        line_end=38,
        citation_snippet="rows = db.query(sql)",
        source_tool="semgrep",
        confidence=0.9,
        severity="high",
    )


def test_structural_claim_round_trip_is_idempotent_and_scoped(tmp_config):
    db.init_db(tmp_config)
    finding = _finding()
    finding_id = db.insert_finding(finding, tmp_config)
    evidence = build_python_slice(RetrievalIndex().build(UAT), finding)
    assert evidence is not None
    claim = claim_from_slice(finding_id, evidence)

    first = db.upsert_security_claim(claim, tmp_config)
    second = db.upsert_security_claim(claim, tmp_config)
    assert first == second
    stored = db.list_security_claims(finding_id, tmp_config)[0]
    assert stored.sink_evidence and "db.query(sql)" in stored.sink_evidence.source
    assert any("request.args.get" in item.source for item in stored.source_evidence)

    verification = verify_structural_claim(
        stored, evidence
    )
    first_verification = db.upsert_claim_verification(verification, tmp_config)
    second_verification = db.upsert_claim_verification(verification, tmp_config)
    assert first_verification == second_verification
    saved = db.list_claim_verifications(stored.id, tmp_config)[0]
    assert saved.status is ClaimVerificationStatus.VERIFIED
    assert "exploitability remain unverified" in saved.reason


def test_unresolved_dependency_produces_incomplete_verification(tmp_config, tmp_path):
    db.init_db(tmp_config)
    (tmp_path / "svc.py").write_text(
        "import os\n\ndef run():\n    os.system(plugin_command)\n"
    )
    finding = Finding(
        repo_id="r", title="Command injection [CWE-78]", file="svc.py",
        line_start=4, line_end=4, citation_snippet="os.system(plugin_command)",
        source_tool="semgrep", confidence=0.8, severity="high",
    )
    finding_id = db.insert_finding(finding, tmp_config)
    evidence = build_python_slice(RetrievalIndex().build(tmp_path), finding)
    assert evidence is not None
    claim = claim_from_slice(finding_id, evidence).model_copy(update={"id": 1})

    verification = verify_structural_claim(claim, evidence)

    assert verification.status is ClaimVerificationStatus.INCOMPLETE
    assert verification.checks["source_present"] is False
    assert "plugin_command" in verification.reason
