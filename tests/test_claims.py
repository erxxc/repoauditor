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
    claim = claim_from_slice(finding_id, evidence, "commit-abc")

    first = db.upsert_security_claim(claim, tmp_config)
    second = db.upsert_security_claim(claim, tmp_config)
    assert first == second
    stored = db.list_security_claims(finding_id, tmp_config)[0]
    assert stored.entry_evidence
    assert '@catalog_bp.route("/products/search")' in stored.entry_evidence[0].source
    assert stored.sink_evidence and "db.query(sql)" in stored.sink_evidence.source
    assert any("request.args.get" in item.source for item in stored.source_evidence)

    verification = verify_structural_claim(stored, UAT, "commit-abc")
    first_verification = db.upsert_claim_verification(verification, tmp_config)
    second_verification = db.upsert_claim_verification(verification, tmp_config)
    assert first_verification == second_verification
    saved = db.list_claim_verifications(stored.id, tmp_config)[0]
    assert saved.status is ClaimVerificationStatus.STRUCTURALLY_VERIFIED
    assert "real-world risk are not validated" in saved.reason
    assert saved.checks["http_entrypoint_present"] is True
    assert saved.checks["attacker_input_source_present"] is True
    assert saved.checks["control_candidate_present"] is False


def test_checker_identifies_control_syntax_on_local_def_use_without_proving_effectiveness(
    tmp_path,
):
    (tmp_path / "svc.py").write_text(
        "import os\n"
        "from flask import request\n\n"
        "@app.route('/run')\n"
        "def run():\n"
        "    command = request.args.get('cmd', '')\n"
        "    safe = sanitize_command(command)\n"
        "    os.system(safe)\n"
    )
    finding = Finding(
        repo_id="r", title="Command injection [CWE-78]", file="svc.py",
        line_start=8, line_end=8, citation_snippet="os.system(safe)",
        source_tool="semgrep", confidence=0.8, severity="high",
    )
    evidence = build_python_slice(RetrievalIndex().build(tmp_path), finding)
    assert evidence is not None and evidence.sanitizer_candidates
    claim = claim_from_slice(1, evidence, "commit-abc").model_copy(update={"id": 1})

    verification = verify_structural_claim(claim, tmp_path, "commit-abc")

    assert verification.status is ClaimVerificationStatus.STRUCTURALLY_VERIFIED
    assert verification.checks["http_entrypoint_present"] is True
    assert verification.checks["attacker_input_source_present"] is True
    assert verification.checks["control_candidate_present"] is True
    assert verification.checks["control_on_local_def_use"] is True
    assert "control effectiveness" in verification.reason


def test_checker_independently_verifies_direct_python_caller_evidence(
    tmp_path, tmp_config
):
    db.init_db(tmp_config)
    (tmp_path / "svc.py").write_text(
        "import os\n\n"
        "def run(command):\n"
        "    os.system(command)\n"
    )
    (tmp_path / "handler.py").write_text(
        "from svc import run\n\n"
        "def handle(value):\n"
        "    return run(value)\n"
    )
    finding = Finding(
        repo_id="r", title="Command injection [CWE-78]", file="svc.py",
        line_start=4, line_end=4, citation_snippet="os.system(command)",
        source_tool="semgrep", confidence=0.8, severity="high",
    )
    evidence = build_python_slice(RetrievalIndex().build(tmp_path), finding)
    assert evidence is not None
    assert len(evidence.caller_evidence) == 1
    assert evidence.caller_evidence[0].file == "handler.py"
    finding_id = db.insert_finding(finding, tmp_config)
    claim = claim_from_slice(finding_id, evidence, "commit-abc")
    claim_id = db.upsert_security_claim(claim, tmp_config)
    claim = db.list_security_claims(finding_id, tmp_config)[0]
    assert claim.id == claim_id
    assert claim.caller_evidence[0].file == "handler.py"

    verification = verify_structural_claim(claim, tmp_path, "commit-abc")

    assert verification.status is ClaimVerificationStatus.STRUCTURALLY_VERIFIED
    assert verification.checks["caller_evidence_present"] is True
    assert verification.checks["direct_callers_verified"] is True
    assert "not runtime reachability" in verification.reason


def test_checker_refutes_forged_direct_caller_evidence(tmp_path):
    (tmp_path / "svc.py").write_text(
        "import os\n\ndef run(command):\n    os.system(command)\n"
    )
    (tmp_path / "handler.py").write_text(
        "from svc import run\n\ndef handle(value):\n    return run(value)\n"
    )
    finding = Finding(
        repo_id="r", title="Command injection [CWE-78]", file="svc.py",
        line_start=4, line_end=4, citation_snippet="os.system(command)",
        source_tool="semgrep", confidence=0.8, severity="high",
    )
    evidence = build_python_slice(RetrievalIndex().build(tmp_path), finding)
    assert evidence is not None
    claim = claim_from_slice(1, evidence, "commit-abc").model_copy(update={"id": 1})
    forged = claim.model_copy(update={
        "caller_evidence": [
            claim.caller_evidence[0].model_copy(update={"source": "return safe(value)"})
        ]
    })

    verification = verify_structural_claim(forged, tmp_path, "commit-abc")

    assert verification.status is ClaimVerificationStatus.STRUCTURALLY_REFUTED
    assert verification.checks["direct_callers_verified"] is False
    assert "direct-caller evidence" in verification.reason


def test_checker_verifies_authorization_candidate_syntax_not_effectiveness(
    tmp_path, tmp_config
):
    db.init_db(tmp_config)
    (tmp_path / "svc.py").write_text(
        "import os\n"
        "from flask import request\n\n"
        "@app.route('/run/<job_id>')\n"
        "@owns_resource('job')\n"
        "def run(job_id):\n"
        "    command = request.args.get('cmd', '')\n"
        "    os.system(command)\n"
    )
    finding = Finding(
        repo_id="r", title="Command injection [CWE-78]", file="svc.py",
        line_start=8, line_end=8, citation_snippet="os.system(command)",
        source_tool="semgrep", confidence=0.8, severity="high",
    )
    finding_id = db.insert_finding(finding, tmp_config)
    evidence = build_python_slice(RetrievalIndex().build(tmp_path), finding)
    assert evidence is not None and len(evidence.authorization_candidates) == 1
    claim_id = db.upsert_security_claim(
        claim_from_slice(finding_id, evidence, "commit-abc"), tmp_config
    )
    claim = db.list_security_claims(finding_id, tmp_config)[0]
    assert claim.id == claim_id
    assert claim.authorization_evidence[0].source == "@owns_resource('job')"

    verification = verify_structural_claim(claim, tmp_path, "commit-abc")

    assert verification.status is ClaimVerificationStatus.STRUCTURALLY_VERIFIED
    assert verification.checks["authorization_candidate_present"] is True
    assert verification.checks["authorization_syntax_verified"] is True
    assert "not authentication, scope, or control effectiveness" in verification.reason


def test_checker_does_not_treat_authentication_as_authorization(tmp_path):
    (tmp_path / "svc.py").write_text(
        "import os\n\n"
        "@login_required\n"
        "def run(command):\n"
        "    current_customer_id()\n"
        "    os.system(command)\n"
    )
    finding = Finding(
        repo_id="r", title="Command injection [CWE-78]", file="svc.py",
        line_start=6, line_end=6, citation_snippet="os.system(command)",
        source_tool="semgrep", confidence=0.8, severity="high",
    )
    evidence = build_python_slice(RetrievalIndex().build(tmp_path), finding)
    assert evidence is not None
    assert evidence.authorization_candidates == []
    claim = claim_from_slice(1, evidence, "commit-abc").model_copy(update={"id": 1})

    verification = verify_structural_claim(claim, tmp_path, "commit-abc")

    assert verification.status is ClaimVerificationStatus.STRUCTURALLY_VERIFIED
    assert verification.checks["authorization_candidate_present"] is False
    assert verification.checks["authorization_syntax_verified"] is False


def test_checker_refutes_forged_authorization_evidence(tmp_path):
    (tmp_path / "svc.py").write_text(
        "import os\n\n"
        "@owns_resource('job')\n"
        "def run(command):\n"
        "    os.system(command)\n"
    )
    finding = Finding(
        repo_id="r", title="Command injection [CWE-78]", file="svc.py",
        line_start=5, line_end=5, citation_snippet="os.system(command)",
        source_tool="semgrep", confidence=0.8, severity="high",
    )
    evidence = build_python_slice(RetrievalIndex().build(tmp_path), finding)
    assert evidence is not None
    claim = claim_from_slice(1, evidence, "commit-abc").model_copy(update={"id": 1})
    forged = claim.model_copy(update={
        "authorization_evidence": [
            claim.authorization_evidence[0].model_copy(
                update={"source": "@require_admin"}
            )
        ]
    })

    verification = verify_structural_claim(forged, tmp_path, "commit-abc")

    assert verification.status is ClaimVerificationStatus.STRUCTURALLY_REFUTED
    assert verification.checks["authorization_syntax_verified"] is False


def test_checker_refutes_forged_entrypoint_evidence():
    finding = _finding()
    evidence = build_python_slice(RetrievalIndex().build(UAT), finding)
    assert evidence is not None
    claim = claim_from_slice(1, evidence, "commit-abc").model_copy(update={"id": 1})
    forged_entry = claim.entry_evidence[0].model_copy(
        update={"source": '@catalog_bp.route("/admin-only")'}
    )
    forged = claim.model_copy(update={"entry_evidence": [forged_entry]})

    verification = verify_structural_claim(forged, UAT, "commit-abc")

    assert verification.status is ClaimVerificationStatus.STRUCTURALLY_REFUTED
    assert verification.checks["evidence_matches_snapshot"] is False


def test_plain_function_parameter_is_not_claimed_as_attacker_controlled(tmp_path):
    (tmp_path / "svc.py").write_text(
        "import os\n\n"
        "def run(command):\n"
        "    os.system(command)\n"
    )
    finding = Finding(
        repo_id="r", title="Command injection [CWE-78]", file="svc.py",
        line_start=4, line_end=4, citation_snippet="os.system(command)",
        source_tool="semgrep", confidence=0.8, severity="high",
    )
    evidence = build_python_slice(RetrievalIndex().build(tmp_path), finding)
    assert evidence is not None
    claim = claim_from_slice(1, evidence, "commit-abc").model_copy(update={"id": 1})

    verification = verify_structural_claim(claim, tmp_path, "commit-abc")

    assert verification.status is ClaimVerificationStatus.STRUCTURALLY_VERIFIED
    assert verification.checks["http_entrypoint_present"] is False
    assert verification.checks["attacker_input_source_present"] is False


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
    claim = claim_from_slice(finding_id, evidence, "commit-abc").model_copy(
        update={"id": 1}
    )

    verification = verify_structural_claim(claim, tmp_path, "commit-abc")

    assert verification.status is ClaimVerificationStatus.VERIFICATION_INCOMPLETE
    assert verification.checks["certificate_complete"] is False
    assert "required source" in verification.reason


def test_independent_checker_refutes_forged_certificate_text():
    finding = _finding()
    evidence = build_python_slice(RetrievalIndex().build(UAT), finding)
    assert evidence is not None
    claim = claim_from_slice(1, evidence, "commit-abc").model_copy(update={"id": 1})
    assert claim.sink_evidence is not None
    forged_sink = claim.sink_evidence.model_copy(
        update={"source": "rows = db.query(sanitized_sql)"}
    )
    forged = claim.model_copy(
        update={
            "sink_evidence": forged_sink,
            "path_nodes": [
                forged_sink if item == claim.sink_evidence else item
                for item in claim.path_nodes
            ],
        }
    )

    verification = verify_structural_claim(forged, UAT, "commit-abc")

    assert verification.status is ClaimVerificationStatus.STRUCTURALLY_REFUTED
    assert verification.checks["evidence_matches_snapshot"] is False


def test_independent_checker_refutes_stale_snapshot_commit():
    finding = _finding()
    evidence = build_python_slice(RetrievalIndex().build(UAT), finding)
    assert evidence is not None
    claim = claim_from_slice(1, evidence, "commit-old").model_copy(update={"id": 1})

    verification = verify_structural_claim(claim, UAT, "commit-new")

    assert verification.status is ClaimVerificationStatus.STRUCTURALLY_REFUTED
    assert verification.checks["snapshot_matches"] is False


def test_independent_checker_requires_snapshot_binding():
    finding = _finding()
    evidence = build_python_slice(RetrievalIndex().build(UAT), finding)
    assert evidence is not None
    claim = claim_from_slice(1, evidence, None).model_copy(update={"id": 1})

    verification = verify_structural_claim(claim, UAT, "commit-abc")

    assert verification.status is ClaimVerificationStatus.VERIFICATION_INCOMPLETE
    assert verification.checks["snapshot_bound"] is False
