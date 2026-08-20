from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / (
    "docs/optimizations/"
    "opt-014-ukds-registration-terms-qualification-receipt-2026-08-18.json"
)


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _assert_bound(record: dict) -> None:
    path = (RECEIPT.parent / record["path"]).resolve()
    assert hashlib.sha256(path.read_bytes()).hexdigest() == record["sha256"]


def test_receipt_binds_design_and_prior_qualification() -> None:
    payload = _payload()

    assert payload["status"] == "authorization-pending"
    _assert_bound(payload["design"])
    _assert_bound(payload["prior_qualification"])
    assert payload["prior_qualification"]["overall_state"] == "conditionally-qualified"
    assert payload["prior_qualification"]["unresolved_gates"] == [
        "G06",
        "G08",
        "G10",
        "G11",
        "G12",
    ]
    assert payload["prior_qualification"]["data_gate_cleared"] is False


def test_receipt_freezes_exact_study_and_only_unresolved_gates() -> None:
    payload = _payload()
    identity = payload["fixed_identity"]
    gates = payload["qualification_contract"]["gates"]

    assert identity["study_number"] == "9285"
    assert identity["doi"] == "10.5255/UKDA-SN-9285-1"
    assert identity["edition"] == 1
    assert identity["source_acquisition_selection"] is False
    assert [gate["gate_id"] for gate in gates] == [
        "G06",
        "G08",
        "G10",
        "G11",
        "G12",
    ]
    assert "No favorable inference" in payload["qualification_contract"][
        "evidence_rule"
    ]


def test_receipt_keeps_credentials_and_identity_owner_private() -> None:
    contract = _payload()["human_control_contract"]
    ceilings = _payload()["resource_ceilings"]

    assert contract["maximum_new_accounts"] == 1
    assert contract["maximum_login_or_registration_sessions"] == 1
    assert contract["maximum_eul_acceptances"] == 1
    assert contract["maximum_human_attestations"] == 1
    assert len(contract["agent_must_not_receive_or_store"]) == 4
    assert ceilings["new_accounts"] == 1
    assert ceilings["login_or_registration_sessions"] == 1
    assert ceilings["eul_acceptances"] == 1
    assert "identity-provider hosts" in ceilings[
        "owner_private_identity_provider_navigation"
    ]


def test_receipt_stops_before_request_download_or_commercial_permission() -> None:
    payload = _payload()
    ceilings = payload["resource_ceilings"]
    statement = payload["authorization"]["required_statement"]

    assert ceilings["dataset_requests_or_orders"] == 0
    assert ceilings["dataset_or_data_file_downloads"] == 0
    assert ceilings["raw_records_read"] == 0
    assert ceilings["applications_inquiries_or_contacts"] == 0
    assert ceilings["purchases_or_payments"] == 0
    assert "commercial use" in statement
    assert "immediate stop" in statement
    assert "adding study 9285 to an account" in statement


def test_receipt_keeps_store_outcomes_and_lifecycle_immutable() -> None:
    payload = _payload()
    ceilings = payload["resource_ceilings"]
    boundary = payload["result_boundary"]

    assert ceilings["network_uploads_by_agent"] == ceilings["provider_calls"] == 0
    assert ceilings["production_store_reads"] == 0
    assert ceilings["production_store_mutations"] == 0
    assert ceilings["assessments_written"] == ceilings["labels_written"] == 0
    assert "may not store personal or account information" in boundary
    assert "clear the OPT-014 data gate" in boundary
    assert "change OPT-014 status" in boundary
