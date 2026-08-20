from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-010-java-ssrf-retained-source-screen-receipt-2026-08-20.json"


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_receipt_binds_qualification_base_capacity_and_instruments():
    payload = _payload()
    for record in payload["frozen_inputs"].values():
        if isinstance(record, dict):
            assert _sha256(ROOT / record["path"]) == record["sha256"]
    for record in payload["frozen_instruments"].values():
        assert _sha256(ROOT / record["path"]) == record["sha256"]


def test_exactly_two_retained_java_subjects_are_frozen():
    subjects = _payload()["frozen_subjects"]
    assert [(item["source_family"], item["exact_commit"]) for item in subjects] == [
        ("theonedev/onedev", "89e2f09b7b0cd9682a32a8b4a1ed863f791570ea"),
        ("Athou/commafeed", "41fc77322cdc02ebe685a1cc1a81e7a5910e5174"),
    ]
    assert all(item["language"] == "Java" and item["mechanism"] == "ssrf" for item in subjects)


def test_base_capacity_is_frozen_and_ruby_forces_no_packet():
    contract = _payload()["screen_contract"]
    base = contract["base_aggregate"]
    assert base["by_supported_family"] == {
        "Java": 0,
        "Python": 29,
        "Ruby": 0,
        "TypeScript": 19,
    }
    assert base["capped_packet_capacity"] == 39
    assert base["provisionally_feasible"] is False
    assert "Ruby remains zero" in contract["recalculation"]
    assert "no packet may be constructed" in contract["recalculation"]


def test_screen_is_aggregate_only_and_routes_source_scarcity():
    contract = _payload()["screen_contract"]
    assert "inclusive-transitive" in contract["eligibility"]
    assert "Ruby source scarcity" in contract["routing"]["java_groups_positive"]
    assert "Java and Ruby source scarcity" in contract["routing"]["java_groups_zero"]
    assert "Do not persist normalized candidate" in contract["result_rule"]
    assert "subject-level counts" in contract["result_rule"]


def test_runtime_and_resource_boundaries_are_exact_and_offline():
    payload = _payload()
    runtime = payload["runtime_contract"]
    assert runtime["semgrep_version"] == "1.170.0"
    requirements = " ".join(runtime["requirements"])
    assert "SEMGREP_LOG_FILE" in requirements
    assert "SEMGREP_VERSION_CACHE_PATH" in requirements
    assert "no-retry" not in requirements
    assert "retry" in requirements
    ceilings = payload["resource_ceilings"]
    assert ceilings["maximum_elapsed_minutes"] == 30
    assert ceilings["maximum_new_data_bytes"] == 10 * 1024**2
    assert ceilings["frozen_snapshot_subjects"] == 2
    assert ceilings["runtime_import_checks"] == 1
    assert ceilings["logical_scanner_processes"] == 2
    for field, value in ceilings.items():
        if field not in {
            "maximum_elapsed_minutes",
            "maximum_new_data_bytes",
            "frozen_snapshot_subjects",
            "runtime_import_checks",
            "logical_scanner_processes",
        }:
            assert value in {0, 0.0}


def test_receipt_is_pending_and_cannot_construct_packet_or_advance_opt010():
    payload = _payload()
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    statement = payload["authorization"]["required_statement"]
    assert "forbidding packet construction" in statement
    assert "subject-level counts" in statement
    assert "OPT-010 promotion or closure" in statement
