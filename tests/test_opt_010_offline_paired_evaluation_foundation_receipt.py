from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-010-offline-paired-evaluation-foundation-receipt-2026-08-20.json"


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_receipt_binds_completed_prerequisites_and_unchanged_instruments():
    payload = _payload()
    for name, record in payload["frozen_inputs"].items():
        if isinstance(record, dict):
            if name == "agentic_gate":
                assert len(record["sha256"]) == 64
            else:
                assert _sha256(ROOT / record["path"]) == record["sha256"]
    for record in payload["frozen_implementation_bindings"].values():
        assert _sha256(ROOT / record["path"]) == record["sha256"]


def test_supported_envelope_is_prospective_and_preserves_outer_denominator():
    envelope = _payload()["supported_qualification_envelope"]
    assert envelope["freeze_before_candidate_or_outcome_access"] is True
    assert envelope["supported_subject_languages"] == ["Python", "TypeScript", "Java", "Ruby"]
    assert envelope["unsupported_outer_denominator_languages"] == ["Go", "Rust"]
    assert envelope["outer_subject_denominator"] == 6
    assert "not silently dropped" in envelope["unsupported_rule"]


def test_packet_and_decision_rules_are_frozen_before_outcomes():
    payload = _payload()
    packet = payload["frozen_future_packet_contract"]
    rules = payload["frozen_future_decision_rules"]
    assert packet["packet_size"] == 40
    assert packet["ordering"].startswith("Outcome-blind")
    assert "cannot be checked only after" not in packet["both_class_rule"]
    assert "Agent recall is at least baseline recall" in rules["G04_pass"]
    assert "strictly better on at least one" in rules["G03b_pass"]
    assert "blocks a pass" in rules["zero_denominator_rule"]


def test_offline_runner_is_eval_only_and_tool_bounded():
    runner = _payload()["paired_runner_contract"]
    assert runner["production_integration"] is False
    assert runner["offline_backend"] .startswith("Scripted deterministic fixtures only")
    assert runner["agent_tool_configuration"]["maximum_agent_iterations"] == 3
    assert runner["agent_tool_configuration"]["maximum_tool_calls_per_identity"] == 12


def test_all_live_prospective_and_mutating_activity_is_zero():
    ceilings = _payload()["resource_ceilings"]
    zero_fields = [key for key, value in ceilings.items() if key not in {
        "maximum_elapsed_minutes", "maximum_new_data_bytes"
    }]
    assert all(ceilings[key] == 0 for key in zero_fields)


def test_foundation_does_not_claim_g03b_g04_or_opt010_complete():
    payload = _payload()
    statement = payload["authorization"]["required_statement"]
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert "cannot execute or pass G03b" in payload["result_boundary"]
    assert "empirical recall evaluation" in statement
    assert "OPT-010 promotion or closure" in statement
