from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFERRAL = ROOT / (
    "docs/optimizations/"
    "opt-014-ukds-registration-terms-qualification-deferral-2026-08-18.json"
)


def _payload() -> dict:
    return json.loads(DEFERRAL.read_text(encoding="utf-8"))


def _assert_bound(record: dict) -> None:
    path = (DEFERRAL.parent / record["path"]).resolve()
    assert hashlib.sha256(path.read_bytes()).hexdigest() == record["sha256"]


def test_deferral_binds_unexecuted_receipt_and_prior_qualification() -> None:
    payload = _payload()

    assert payload["status"] == "ukds-registration-path-deferred-unexecuted"
    _assert_bound(payload["receipt"])
    _assert_bound(payload["prior_qualification"])
    assert payload["receipt"]["authorization_granted"] is False
    assert payload["receipt"]["execution_started"] is False
    assert payload["prior_qualification"]["study_9285_state"] == (
        "conditionally-qualified"
    )


def test_deferral_blocks_only_ukds_path_and_preserves_opt014() -> None:
    path_state = _payload()["path_state"]

    assert path_state["state"] == "deferred-commercial-rights-uncertain"
    assert path_state["opt_014_status"] == "open-data-gated"
    assert path_state["opt_014_closed"] is False
    assert path_state["data_gate_cleared"] is False
    assert path_state["source_selected"] is False
    assert "Only the human-mediated UK Data Service" in path_state["scope_of_block"]
    assert "does not classify study 9285 as commercially prohibited" in path_state[
        "bounded_interpretation"
    ]


def test_deferral_records_no_account_agreement_data_or_store_activity() -> None:
    accounting = _payload()["accounting"]

    zero_fields = [
        "network_reads",
        "network_uploads",
        "provider_calls",
        "provider_reported_tokens",
        "accounts_created",
        "login_or_registration_sessions",
        "eul_acceptances",
        "study_requests_or_orders",
        "dataset_downloads",
        "raw_records_read",
        "outcomes_read",
        "production_store_reads",
        "production_store_mutations",
        "assessments_written",
        "labels_written",
        "simulation_runs",
        "model_training_runs",
        "rescoring_runs",
        "opt_014_lifecycle_changes",
    ]
    assert all(accounting[field] == 0 for field in zero_fields)
    assert accounting["provider_cost_usd"] == 0.0


def test_deferral_keeps_reversible_unblock_conditions_and_options() -> None:
    payload = _payload()

    assert len(payload["unblock_conditions"]) == 4
    assert len(payload["commercially_neutral_next_options"]) == 5
    assert payload["recommended_sequence"][0].startswith(
        "Run the license-first source screen"
    )
    assert any(
        option["option"] == "prospective-commercial-rights-panel"
        for option in payload["commercially_neutral_next_options"]
    )
