from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from repoauditor.eval.opt010_java_ssrf_supplemental_qualification import (
    RULE_DIGEST,
    RULE_ID,
    canonical_scratch_rule_id,
    control_set_digest,
    expectation_passed,
)


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-010-java-ssrf-supplemental-rule-qualification-receipt-2026-08-20.json"
ARTIFACT = ROOT / "data/artifacts/opt010-java-ssrf-supplemental-qualification/qualification-artifact.json"
RESULT = ROOT / "docs/optimizations/opt-010-java-ssrf-supplemental-rule-qualification-result-2026-08-20.json"


def test_candidate_rule_digest_reproduces_from_frozen_receipt():
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    payload = json.dumps(
        {"rules": [receipt["candidate_rule_contract"]["rule"]]},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode() + b"\n"
    assert hashlib.sha256(payload).hexdigest() == RULE_DIGEST


def test_scratch_rule_identity_is_canonicalized_only_by_exact_suffix():
    assert canonical_scratch_rule_id(RULE_ID) == RULE_ID
    assert canonical_scratch_rule_id(f"temporary.config.{RULE_ID}") == RULE_ID
    assert canonical_scratch_rule_id(f"{RULE_ID}.different") != RULE_ID


def test_control_expectations_are_exact_and_fail_closed():
    assert expectation_passed("raised-exactly-once", 1) is True
    assert expectation_passed("raised-exactly-once", 0) is False
    assert expectation_passed("raised-exactly-once", 2) is False
    assert expectation_passed("absent", 0) is True
    assert expectation_passed("absent", 1) is False
    assert expectation_passed("unknown", 0) is False


def test_control_set_digest_is_order_and_identity_bound():
    rows = [
        {"order": 1, "id": "positive", "expectation": "raised-exactly-once", "path": "a.java", "sha256": "a" * 64},
        {"order": 2, "id": "clean", "expectation": "absent", "path": "b.java", "sha256": "b" * 64},
    ]
    assert control_set_digest(rows) != control_set_digest(list(reversed(rows)))


def test_qualification_result_is_bounded_and_preserves_production_state():
    if not RESULT.exists():
        pytest.skip("authorized Java SSRF qualification result not yet written")
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    artifact = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    assert result["status"] in {
        "qualified-synthetic-scratch-rule",
        "completed-negative-synthetic-qualification",
    }
    assert result["qualification"]["controls_total"] == 6
    assert result["qualification"]["positive_controls"] == 3
    assert result["qualification"]["clean_controls"] == 3
    assert artifact["candidate_rule_sha256"] == RULE_DIGEST
    assert artifact["production_rule_edited_or_promoted"] is False
    assert artifact["repository_or_production_source_reads"] == 0
    assert artifact["finding_or_candidate_identities_persisted_or_disclosed"] == 0
    assert result["boundaries"] == {
        "production_rule_edited_or_promoted": False,
        "retained_source_rescan_started": False,
        "packet_frozen": False,
        "g03b_decided": False,
        "g04_decided": False,
        "opt010_status_changed": False,
    }


def test_qualification_has_exact_process_counts_zero_external_activity_and_unchanged_state():
    if not RESULT.exists():
        pytest.skip("authorized Java SSRF qualification result not yet written")
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    accounting = result["resource_accounting"]
    assert accounting["runtime_import_checks"] == 1
    assert accounting["logical_scanner_processes"] == 6
    assert accounting["new_data_bytes"] <= 5 * 1024**2
    assert accounting["elapsed_seconds"] <= 10 * 60
    for field, value in accounting.items():
        if field not in {
            "runtime_import_checks",
            "logical_scanner_processes",
            "new_data_bytes",
            "elapsed_seconds",
        }:
            assert value in {0, 0.0}
    assert result["production_supplemental_ruleset"]["byte_identical"] is True
    assert result["production_store"]["byte_identical"] is True
