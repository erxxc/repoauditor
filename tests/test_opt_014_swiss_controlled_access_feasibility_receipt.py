from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / (
    "docs/optimizations/"
    "opt-014-swiss-controlled-access-feasibility-receipt-2026-08-18.json"
)


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _assert_bound(record: dict) -> None:
    path = (RECEIPT.parent / record["path"]).resolve()
    assert hashlib.sha256(path.read_bytes()).hexdigest() == record["sha256"]


def test_receipt_binds_design_and_negative_swiss_discovery() -> None:
    payload = _payload()

    assert payload["status"] == "authorization-pending"
    _assert_bound(payload["design"])
    _assert_bound(payload["swiss_discovery"])
    assert payload["swiss_discovery"]["full_tier_candidates"] == 0
    assert payload["swiss_discovery"]["acquisition_ready_candidates"] == 0
    assert payload["swiss_discovery"]["data_gate_cleared"] is False


def test_receipt_freezes_three_state_public_metadata_gates() -> None:
    contract = _payload()["qualification_contract"]

    assert contract["gate_states"] == [
        "documented-pass",
        "documented-fail",
        "unresolved",
    ]
    assert len(contract["gates"]) == 10
    assert "no favorable inference" in contract["evidence_rule"]
    assert "publicly-actionable" in contract["overall_states"]
    assert "do not transcribe" in contract["outcome_blinding"][
        "incidental_value_quarantine"
    ]


def test_receipt_has_exact_hosts_and_zero_restricted_activity() -> None:
    ceilings = _payload()["resource_ceilings"]

    assert ceilings["maximum_metadata_documents"] == 24
    assert ceilings["maximum_result_documents"] == 1
    assert len(ceilings["network_hosts"]) == 12
    assert "www.bfs.admin.ch" in ceilings["network_hosts"]
    assert "www.ncsc.admin.ch" in ceilings["network_hosts"]
    assert "www.fedlex.admin.ch" in ceilings["network_hosts"]
    assert "www.edoeb.admin.ch" in ceilings["network_hosts"]
    assert ceilings["network_uploads"] == ceilings["provider_calls"] == 0
    assert ceilings["dataset_downloads"] == ceilings["raw_records_read"] == 0
    assert ceilings["applications_or_contacts"] == 0
    assert ceilings["production_store_reads"] == 0
    assert ceilings["production_store_mutations"] == 0


def test_receipt_stops_before_access_selection_or_lifecycle_change() -> None:
    payload = _payload()
    statement = payload["authorization"]["required_statement"]

    assert "terms acceptance" in statement
    assert "restricted-data requests" in statement
    assert "source acquisition selection" in statement
    assert "OPT-014 promotion or closure" in statement
    assert "may not disclose records or outcomes" in payload["result_boundary"]
    assert "clear the OPT-014 data gate" in payload["result_boundary"]
