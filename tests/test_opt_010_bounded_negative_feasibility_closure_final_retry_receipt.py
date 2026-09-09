from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-010-bounded-negative-feasibility-closure-final-retry-receipt-2026-08-20.json"


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_final_receipt_binds_immutable_prior_receipts_and_retained_twelve():
    payload = _payload()
    for name in ("original_receipt", "corrected_retry_receipt"):
        record = payload["retained_authority"][name]
        assert _sha256(ROOT / record["path"]) == record["sha256"]
    retained = payload["retained_twelve_reconciliations"]
    assert len(retained) == 12
    assert {
        record["path"]: record["sha256"] for record in retained
    } == {
        "tests/test_opt_009_closure_result.py": "8a4c392e8e352fe4fcdf399be240aeb3f0503fe286b6d518aafdb5f74f53bd64",
        "tests/test_opt_009_corrected_retry_receipt.py": "e28723668c2665f003b19eb1c3a5918fb80063753ce221e511c293dc6268a237",
        "tests/test_opt_009_serialization_retry_receipt.py": "e0f60ad81abd31e055b7fea3ac8c33034cf5e943e679d2191d73c52060567979",
        "tests/test_opt_010_architecture_mechanism_eligibility_final_retry_receipt.py": "0d902c4c2731cf2b0ca033c2f5ecc0d5961e46173570a6a8c2c29c7c559ab7ab",
        "tests/test_opt_010_bounded_negative_feasibility_closure_receipt.py": "ede97c5eba532a1638fbc7a7684ed23a81f63e82009342274ef7d8ad9cf41635",
        "tests/test_opt_010_java_ruby_source_augmentation_selection_receipt.py": "f4f273d520d453cd51930099dd80f9b0391d1722588e523dbe5a698d1b56f3e8",
        "tests/test_opt_010_offline_paired_evaluation_foundation_receipt.py": "ed7ddea6dbf1c539744243f1a7c58ca945396d23182254b26fe08794b10cb5d6",
        "tests/test_opt_010_prospective_source_selection_receipt.py": "ef48560ae6cb6ace45b70a7505acf196f9b671e6b8d37db80dc0fccad10d2fe6",
        "tests/test_opt_014_descriptive_scope_closure.py": "e0413a5d10e1a81012348ab45cbcb4572f12eb38f6ff45c35e2716623d2119c1",
        "tests/test_opt_014_descriptive_scope_closure_receipt.py": "823f1565da3dd81a273f0eef6c0e297c367b7235ad4595b3377279d3fb8a8122",
        "tests/test_opt_014_eligibility_audit.py": "f28d536f492f0fe42d20934992013730f2bc13c53c73d41a8403fea63a5d5dc4",
        "tests/test_opt_014_prior_predictive.py": "8118a2ce80642147c3dd957ef994398811642b6402f919a721a98cfa9a1f388e",
    }


def test_mutable_pre_retry_hashes_are_explicit_historical_records():
    authority = _payload()["retained_authority"]
    assert authority["stopped_result"]["sha256"] == "346db5007ef56b0858c37bce99ada1bf0b1709126a173d8d9fc6d1c78552e368"
    assert authority["stopped_closure_test"]["sha256"] == "cd35b3dd960b36833aa82b850bd7fd7314d5381430b93556919730c7de3d324e"
    assert authority["corrected_retry_receipt_test_before_reconciliation"]["sha256"] == "e2cfc242087ae2f9ddd47c466edd53c584e35f1ac5cc48806c5d02119edf81c5"


def test_only_one_additional_test_reconciliation_is_permitted():
    payload = _payload()
    correction = payload["only_additional_reconciliation"]
    assert payload["allowlist_addition"] == [correction["path"]]
    assert correction["receipt_or_evidence_edits"] == 0
    assert correction["implementation_or_helper_edits"] == 0
    assert "immutable historical receipt evidence" in correction["permitted_change"]


def test_final_retry_remains_zero_activity_and_bounded():
    payload = _payload()
    ceilings = payload["cumulative_resource_ceilings"]
    assert payload["execution"]["lifecycle_after"] == {
        "closed": 35, "open": 0, "total": 35, "remaining_priority": []
    }
    assert payload["execution"]["facade_after"] == "qualified-disabled-and-disconnected"
    assert all(
        value == 0 or value == 0.0
        for key, value in ceilings.items()
        if key not in {"maximum_elapsed_minutes", "maximum_new_data_bytes"}
    )


def test_final_receipt_is_pending_and_requires_exact_authorization():
    payload = _payload()
    statement = payload["authorization"]["required_statement"]
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert "only reconciliation of tests/test_opt_010_bounded_negative_feasibility_closure_corrected_retry_receipt.py" in statement
    assert "twelve completed historical-state reconciliations with 66 focused passes" in statement
    assert "35 closed and zero open" in statement
