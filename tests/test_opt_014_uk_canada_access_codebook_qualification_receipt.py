from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / (
    "docs/optimizations/"
    "opt-014-uk-canada-access-codebook-qualification-receipt-2026-08-18.json"
)


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _assert_bound(record: dict) -> None:
    path = (RECEIPT.parent / record["path"]).resolve()
    assert hashlib.sha256(path.read_bytes()).hexdigest() == record["sha256"]


def test_receipt_binds_design_prior_discovery_and_swiss_result() -> None:
    payload = _payload()

    assert payload["status"] == "authorization-pending"
    _assert_bound(payload["design"])
    _assert_bound(payload["prior_discovery"])
    _assert_bound(payload["swiss_feasibility"])
    assert payload["prior_discovery"]["full_tier_candidates"] == 1
    assert payload["prior_discovery"]["acquisition_ready_candidates"] == 0
    assert payload["prior_discovery"]["data_gate_cleared"] is False


def test_receipt_freezes_fixed_canada_and_bounded_uk_identities() -> None:
    payload = _payload()
    candidates = payload["candidate_contract"]
    ceilings = payload["resource_ceilings"]

    assert candidates["fixed_canadian_identity"]["record_number"] == "5244"
    assert candidates["fixed_canadian_identity"]["detailed_information_id"] == "359489"
    assert candidates["uk_family"]["maximum_exact_release_or_catalog_identities"] == 3
    assert candidates["maximum_total_identities"] == 4
    assert ceilings["maximum_candidate_identities"] == 4
    assert candidates["candidate_ranking"] is False
    assert candidates["source_acquisition_selection"] is False


def test_receipt_has_three_state_outcome_blind_access_gates() -> None:
    contract = _payload()["qualification_contract"]

    assert contract["gate_states"] == [
        "documented-pass",
        "documented-fail",
        "unresolved",
    ]
    assert len(contract["per_identity_gates"]) == 12
    assert "no favorable inference" in contract["evidence_rule"]
    assert "do not transcribe" in contract["outcome_blinding"][
        "incidental_value_quarantine"
    ]


def test_receipt_corrects_exact_hosts_and_keeps_zero_restricted_activity() -> None:
    ceilings = _payload()["resource_ceilings"]

    assert ceilings["maximum_metadata_documents"] == 40
    assert ceilings["maximum_result_documents"] == 1
    assert len(ceilings["network_hosts"]) == 16
    assert "assets.publishing.service.gov.uk" in ceilings["network_hosts"]
    assert "doc.ukdataservice.ac.uk" in ceilings["network_hosts"]
    assert "datacatalogue.ukdataservice.ac.uk" in ceilings["network_hosts"]
    assert "www.statcan.gc.ca" in ceilings["network_hosts"]
    assert "www150.statcan.gc.ca" in ceilings["network_hosts"]
    assert ceilings["network_uploads"] == ceilings["provider_calls"] == 0
    assert ceilings["dataset_downloads"] == ceilings["raw_records_read"] == 0
    assert ceilings["registrations_applications_or_contacts"] == 0
    assert ceilings["production_store_reads"] == 0
    assert ceilings["production_store_mutations"] == 0


def test_receipt_stops_before_access_acquisition_or_lifecycle_change() -> None:
    payload = _payload()
    statement = payload["authorization"]["required_statement"]

    assert "registration" in statement
    assert "terms acceptance" in statement
    assert "source acquisition selection" in statement
    assert "OPT-014 promotion or closure" in statement
    assert "may not inspect or disclose records or outcomes" in payload["result_boundary"]
    assert "clear the OPT-014 data gate" in payload["result_boundary"]
