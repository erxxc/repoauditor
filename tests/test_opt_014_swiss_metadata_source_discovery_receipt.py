from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / (
    "docs/optimizations/opt-014-swiss-metadata-source-discovery-receipt-2026-08-18.json"
)


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _assert_bound(record: dict) -> None:
    path = (RECEIPT.parent / record["path"]).resolve()
    assert hashlib.sha256(path.read_bytes()).hexdigest() == record["sha256"]


def test_opt014_swiss_receipt_binds_design_and_prior_discovery():
    payload = _payload()

    assert payload["status"] == "authorization-pending"
    _assert_bound(payload["design"])
    _assert_bound(payload["prior_discovery"])
    assert payload["prior_discovery"]["data_gate_cleared"] is False
    assert payload["prior_discovery"]["acquisition_ready_candidates"] == 0


def test_opt014_swiss_receipt_is_small_exact_host_and_outcome_blind():
    payload = _payload()
    contract = payload["discovery_contract"]
    ceilings = payload["resource_ceilings"]

    assert contract["jurisdiction"] == "Switzerland"
    assert contract["candidate_ceiling"] == ceilings["maximum_candidate_identities"] == 8
    assert ceilings["maximum_metadata_documents"] == 32
    assert len(ceilings["network_hosts"]) == 12
    assert "www.bfs.admin.ch" in ceilings["network_hosts"]
    assert "www.ncsc.admin.ch" in ceilings["network_hosts"]
    assert "opendata.swiss" in ceilings["network_hosts"]
    assert "do not transcribe" in contract["outcome_blinding"][
        "incidental_value_quarantine"
    ]


def test_opt014_swiss_receipt_has_zero_data_store_or_model_activity():
    ceilings = _payload()["resource_ceilings"]

    assert ceilings["network_uploads"] == ceilings["provider_calls"] == 0
    assert ceilings["provider_reported_tokens"] == ceilings["provider_cost_usd"] == 0
    assert ceilings["dataset_downloads"] == ceilings["raw_records_read"] == 0
    assert ceilings["production_store_reads"] == ceilings["production_store_mutations"] == 0
    assert ceilings["assessments_written"] == ceilings["labels_written"] == 0
    assert ceilings["simulation_runs"] == ceilings["model_training_runs"] == 0
    assert ceilings["rescoring_runs"] == 0


def test_opt014_swiss_receipt_stops_before_selection_or_gate_change():
    payload = _payload()
    statement = payload["authorization"]["required_statement"]

    assert "source acquisition selection" in statement
    assert "adequacy thresholds" in statement
    assert "OPT-014 promotion or closure" in statement
    assert "may not select an acquisition source" in payload["result_boundary"]
    assert "clear the OPT-014 data gate" in payload["result_boundary"]
