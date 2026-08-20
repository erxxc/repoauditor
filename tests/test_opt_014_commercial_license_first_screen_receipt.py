from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / (
    "docs/optimizations/"
    "opt-014-commercial-license-first-screen-receipt-2026-08-18.json"
)


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _assert_bound(record: dict) -> None:
    path = (RECEIPT.parent / record["path"]).resolve()
    assert hashlib.sha256(path.read_bytes()).hexdigest() == record["sha256"]


def test_receipt_binds_all_frozen_evidence_and_deferral() -> None:
    payload = _payload()

    assert payload["status"] == "authorization-pending"
    _assert_bound(payload["design"])
    _assert_bound(payload["prior_discovery"])
    _assert_bound(payload["uk_canada_qualification"])
    _assert_bound(payload["ukds_deferral"])
    assert payload["ukds_deferral"]["state"] == (
        "deferred-commercial-rights-uncertain"
    )
    assert payload["ukds_deferral"]["execution_started"] is False


def test_receipt_is_license_first_and_permissive_only() -> None:
    contract = _payload()["screen_contract"]

    assert contract["license_gate_first"] is True
    assert contract["schema_review_only_after_pass"] is True
    assert "CC BY" in contract["permissive_pass_rule"]
    assert "Open Government Licence" in contract["permissive_pass_rule"]
    assert "share-alike" in contract["conditional_rule"]
    assert "registration/EUL" in contract["fail_rule"]
    assert contract["no_ranking_or_scoring"] is True
    assert len(contract["schema_requirements"]) == 8


def test_receipt_is_low_effort_and_outcome_blind() -> None:
    payload = _payload()
    ceilings = payload["resource_ceilings"]

    assert ceilings["maximum_elapsed_minutes"] == 20
    assert ceilings["maximum_new_data_bytes"] == 5 * 1024 * 1024
    assert ceilings["maximum_candidate_identities"] == 8
    assert ceilings["maximum_new_candidate_identities"] == 4
    assert ceilings["maximum_metadata_documents"] == 24
    assert ceilings["maximum_result_documents"] == 1
    assert ceilings["dataset_downloads"] == ceilings["raw_records_read"] == 0
    assert "do not transcribe" in payload["outcome_blinding"][
        "incidental_value_quarantine"
    ]


def test_receipt_rejects_restricted_activity_and_keeps_store_immutable() -> None:
    ceilings = _payload()["resource_ceilings"]

    assert ceilings["network_uploads"] == ceilings["provider_calls"] == 0
    assert ceilings["registrations_applications_or_contacts"] == 0
    assert ceilings["purchases_payments_or_subscriptions"] == 0
    assert ceilings["production_store_reads"] == 0
    assert ceilings["production_store_mutations"] == 0
    assert ceilings["assessments_written"] == ceilings["labels_written"] == 0
    assert ceilings["simulation_runs"] == ceilings["model_training_runs"] == 0
    assert ceilings["rescoring_runs"] == 0


def test_no_candidate_parks_without_lifecycle_or_opt010_execution() -> None:
    payload = _payload()
    result = payload["result_contract"]
    statement = payload["authorization"]["required_statement"]

    assert "operationally parked" in result["no_full_candidate"]
    assert "still open-data-gated" in result["no_full_candidate"]
    assert "without changing the optimization lifecycle ledger" in result[
        "no_full_candidate"
    ]
    assert "OPT-010" in result["no_full_candidate"]
    assert "OPT-010 execution" in statement
    assert "remain excluded" in statement
    assert "may not" in payload["result_boundary"]
