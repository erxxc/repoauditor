from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / (
    "docs/optimizations/opt-014-metadata-source-discovery-receipt-2026-08-18.json"
)


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def test_opt014_metadata_discovery_receipt_binds_frozen_design():
    payload = _payload()
    design = payload["design"]
    path = (RECEIPT.parent / design["path"]).resolve()

    assert payload["status"] == "authorization-pending"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == design["sha256"]


def test_opt014_metadata_discovery_receipt_is_outcome_blind_and_tiered():
    contract = _payload()["discovery_contract"]

    assert contract["candidate_ceiling"] == 18
    assert set(contract["classification"]["tiers"]) == {
        "full-organization-period-candidate",
        "magnitude-only-candidate",
        "aggregate-context-only",
        "ineligible",
    }
    assert contract["classification"]["no_ranking_or_scoring"] is True
    assert contract["outcome_blinding"]["raw_records_read"] == 0
    assert "do not transcribe" in contract["outcome_blinding"][
        "incidental_value_quarantine"
    ]


def test_opt014_metadata_discovery_receipt_has_exact_zero_data_and_model_activity():
    ceilings = _payload()["resource_ceilings"]

    assert len(ceilings["network_hosts"]) == 18
    assert ceilings["maximum_candidate_identities"] == 18
    assert ceilings["maximum_metadata_documents"] == 72
    assert ceilings["dataset_downloads"] == ceilings["raw_records_read"] == 0
    assert ceilings["network_uploads"] == ceilings["provider_calls"] == 0
    assert ceilings["provider_reported_tokens"] == ceilings["provider_cost_usd"] == 0
    assert ceilings["production_store_reads"] == ceilings["production_store_mutations"] == 0
    assert ceilings["assessments_written"] == ceilings["labels_written"] == 0
    assert ceilings["simulation_runs"] == ceilings["model_training_runs"] == 0
    assert ceilings["rescoring_runs"] == 0


def test_opt014_metadata_discovery_receipt_stops_before_acquisition_or_gate_change():
    payload = _payload()
    statement = payload["authorization"]["required_statement"]

    assert "source acquisition selection" in statement
    assert "adequacy thresholds" in statement
    assert "OPT-014 promotion or closure" in statement
    assert "may not select a source for acquisition" in payload["result_boundary"]
    assert "clear the OPT-014 data gate" in payload["result_boundary"]
