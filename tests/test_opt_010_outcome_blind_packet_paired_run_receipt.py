from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-010-outcome-blind-packet-paired-run-receipt-2026-08-20.json"


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_receipt_binds_completed_wave_architecture_and_foundation():
    payload = _payload()
    for record in payload["frozen_inputs"].values():
        if isinstance(record, dict):
            assert _sha256(ROOT / record["path"]) == record["sha256"]
    for record in payload["frozen_instruments"].values():
        assert _sha256(ROOT / record["path"]) == record["sha256"]


def test_mechanism_mapping_is_frozen_before_any_scanner_artifact_access():
    mapping = _payload()["pre_candidate_mechanism_mapping"]
    assert mapping["freeze_before_scanner_artifact_access"] is True
    assert mapping["cwe_mapping"] == {
        "CWE-89": "sql_injection",
        "CWE-77": "command_injection",
        "CWE-78": "command_injection",
        "CWE-918": "ssrf",
        "CWE-502": "unsafe_deserialization",
    }
    assert mapping["eligible_scanners"] == ["semgrep", "semgrep-supplemental"]


def test_packet_selection_is_exact_outcome_blind_and_fail_closed():
    packet = _payload()["candidate_and_packet_contract"]
    assert "Exactly 40" in packet["selection"]
    assert "outcome-blind" in packet["selection"]
    assert "zero provider calls" in packet["shortfall"]
    assert "disclose no partial packet" in packet["shortfall"]


def test_paired_run_is_blinded_bounded_no_retry_and_scratch_only():
    execution = _payload()["paired_execution"]
    assert execution["provider"] == "anthropic"
    assert execution["model"] == "claude-opus-4-8"
    assert execution["request_maximum_utf8_bytes"] == 120000
    assert "no schema, parse, transport, status, refusal, or other retry" in execution["baseline"]
    assert "no schema, parse, transport, status, refusal, or other retry" in execution["agent"]
    assert "only in scratch" in execution["blinding"]


def test_provider_and_zero_activity_ceilings_are_explicit():
    ceilings = _payload()["resource_ceilings"]
    assert ceilings["packet_identities"] == 40
    assert ceilings["provider_attempts"] == ceilings["public_source_transmissions"] == 360
    assert ceilings["provider_reported_tokens"] == 2500000
    assert ceilings["maximum_known_dated_price_cost_usd"] == 50.0
    assert ceilings["allowed_network_hosts"] == ["api.anthropic.com"]
    for field in (
        "other_network_reads_or_uploads", "repository_materializations",
        "repository_code_executions", "scanner_processes", "production_store_reads",
        "production_store_mutations", "schema_migrations", "human_reviews",
        "outcomes_read", "assessments", "labels", "model_training_runs",
        "rescoring_runs", "workspace_branch_or_index_mutations", "commits",
        "merges", "pushes", "lifecycle_changes",
    ):
        assert ceilings[field] == 0


def test_result_cannot_claim_g03b_g04_or_opt010_complete():
    payload = _payload()
    statement = payload["authorization"]["required_statement"]
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert "cannot access or create human outcomes" in payload["result_boundary"]
    assert "G03b or empirical G04 decisions" in statement
    assert "OPT-010 promotion or closure" in statement
