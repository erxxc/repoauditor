from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-010-java-ruby-source-augmentation-acquisition-screen-corrected-retry-receipt-2026-08-20.json"


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_corrected_receipt_preserves_original_and_stopped_result():
    payload = _payload()
    for record in payload["retained_authority"].values():
        if isinstance(record, dict) and "path" in record:
            assert _sha256(ROOT / record["path"]) == record["sha256"]
    state = payload["retained_authority"]["accepted_state"]
    assert state["artifact_directory_created"] is False
    assert state["logical_scanner_processes"] == 0
    assert state["repositories_materialized"] == 0
    assert state["network_reads"] == 0


def test_added_inputs_and_instruments_are_exactly_digest_bound():
    payload = _payload()
    for section in ("added_frozen_inputs", "added_frozen_instruments"):
        for record in payload[section].values():
            assert _sha256(ROOT / record["path"]) == record["sha256"]


def test_correction_is_only_existing_canaries_and_original_implementation_paths():
    contract = _payload()["correction_contract"]
    assert "byte-for-byte" in contract["scope"]
    assert "exactly one" in contract["java_canary"]
    assert "exactly one" in contract["ruby_canary"]
    assert "helper and focused test already named by the original receipt" in contract["implementation"]


def test_cumulative_ceilings_retain_original_zero_live_boundaries():
    ceilings = _payload()["cumulative_resource_ceilings"]
    assert ceilings["repositories"] == 4
    assert ceilings["logical_scanner_processes"] == 8
    assert ceilings["allowed_network_hosts"] == ["github.com"]
    assert ceilings["maximum_new_data_bytes"] == 15 * 1024**3
    for field, value in ceilings.items():
        if field not in {
            "repositories",
            "runtime_import_checks",
            "logical_scanner_processes",
            "retrieval_index_builds",
            "maximum_elapsed_minutes_per_repository",
            "maximum_total_elapsed_minutes",
            "maximum_new_data_bytes",
            "allowed_network_hosts",
        }:
            assert value in {0, 0.0}


def test_retry_remains_pending_and_cannot_run_on_source_approval_alone():
    payload = _payload()
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    statement = payload["authorization"]["required_statement"]
    assert "accepting the retained stopped preflight" in statement
    assert "one corrected aggregate artifact and result" in statement
    assert "OPT-010 promotion or closure" in statement
