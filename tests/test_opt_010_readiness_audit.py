from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STORE = ROOT / "data/repoauditor.db"
ARTIFACT = ROOT / (
    "docs/optimizations/opt-010-offline-readiness-audit-artifact-2026-08-18.json"
)
RESULT = ROOT / (
    "docs/optimizations/opt-010-offline-readiness-audit-result-2026-08-18.json"
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _artifact() -> dict:
    return json.loads(ARTIFACT.read_text(encoding="utf-8"))


def test_audit_is_aggregate_only_and_store_is_byte_identical():
    before = _sha256(STORE)
    payload = _artifact()
    after = _sha256(STORE)

    assert before == after == payload["store"]["sha256_before"]
    assert payload["store"]["sha256_after"] == before
    assert payload["store"]["byte_identical"] is True
    assert payload["accounting"]["row_identities_emitted"] == 0
    assert payload["accounting"]["source_records_rendered"] == 0


def test_all_seven_gates_are_fail_closed_and_experiment_remains_prohibited():
    payload = _artifact()
    states = {
        gate["gate_id"]: gate["state"] for gate in payload["gate_classification"]
    }

    assert states == {
        "G01": "documented-pass",
        "G02": "partial",
        "G03": "documented-fail",
        "G04": "partial",
        "G05": "partial",
        "G06": "documented-fail",
        "G07": "partial",
    }
    assert payload["decision"]["all_seven_pass"] is False
    assert payload["decision"]["agentic_experiment_permitted"] is False
    assert payload["decision"]["opt_010_status"] == "open-deferred"


def test_usage_abstention_and_verification_evidence_are_aggregate():
    payload = _artifact()
    inventory = payload["aggregate_inventory"]

    assert inventory["usage_accounting"]["attempts"] > 0
    assert inventory["usage_accounting"]["authoritative_usage"] > 0
    assert inventory["usage_accounting"]["explicit_unknown_usage"] > 0
    assert inventory["findings_by_falsification_status"]["unresolved"] > 0
    assert inventory["manual_evidence"]["assessment_abstentions"] > 0
    assert inventory["structural_claims"]["claims"] > 0
    assert inventory["structural_claims"]["snapshot_bound"] > 0


def test_audit_preserves_sec_reserve_and_records_zero_excluded_activity():
    payload = _artifact()
    accounting = payload["accounting"]

    assert payload["sec_edgar_reserve"] == {
        "opt_014_role": "inactive-commercially-permissive-structurally-limited-reserve",
        "selected_or_acquired": False,
        "used_by_opt_010": False,
    }
    zero_fields = (
        "network_reads", "network_uploads", "provider_calls",
        "provider_reported_tokens", "repository_materializations",
        "repository_code_executions", "scanner_processes",
        "agentic_falsification_runs", "production_store_mutations",
        "schema_migrations", "assessments_written", "labels_written",
        "model_training_runs", "rescoring_runs",
    )
    assert all(accounting[field] == 0 for field in zero_fields)


def test_persisted_artifact_retains_receipt_time_input_digests():
    payload = _artifact()
    assert payload["status"] == "offline-remediation-or-evidence-needed"
    assert set(payload["input_digests"]) == {
        "activation_gate",
        "challenger",
        "claims",
        "configuration",
        "opt_014_handoff",
        "optimization_status",
        "production_store",
        "receipt",
        "retrieval_index",
        "sec_edgar_reserve",
        "slicing",
    }
    assert all(len(digest) == 64 for digest in payload["input_digests"].values())


def test_result_binds_artifact_helper_receipt_and_unchanged_store():
    if not RESULT.exists():
        return
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    evidence = result["execution_evidence"]

    assert _sha256(ARTIFACT) == evidence["artifact"]["sha256"]
    assert _sha256(ROOT / evidence["helper"]["path"]) == evidence["helper"]["sha256"]
    assert _sha256(ROOT / evidence["receipt"]["path"]) == evidence["receipt"]["sha256"]
    assert result["store"]["before_sha256"] == result["store"]["after_sha256"]
    assert result["store"]["after_sha256"] == _sha256(STORE)
    assert result["decision"]["agentic_experiment_permitted"] is False
