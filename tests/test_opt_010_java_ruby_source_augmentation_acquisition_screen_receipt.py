from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-010-java-ruby-source-augmentation-acquisition-screen-receipt-2026-08-20.json"


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_receipt_binds_all_frozen_files_and_store():
    payload = _payload()
    for section in ("frozen_inputs", "frozen_instruments"):
        for record in payload[section].values():
            if isinstance(record, dict):
                assert _sha256(ROOT / record["path"]) == record["sha256"]
    assert payload["frozen_inputs"]["production_store_sha256"] == _sha256(
        ROOT / "data/repoauditor.db"
    )


def test_exact_approved_subjects_are_two_java_and_two_ruby():
    subjects = _payload()["frozen_subjects"]
    assert [(item["repository"], item["exact_commit"]) for item in subjects] == [
        ("Suwayomi/Suwayomi-Server", "4b2c19abbc637dfd2c26b9b5eafd326ba92f91ee"),
        ("codelibs/fess", "41f138b5b91af26413ae6cab05bb6acffa6611df"),
        ("Multiwoven/multiwoven", "0a68d209009f9009664e96ef1e5d1f23843781b2"),
        ("docusealco/docuseal", "004a22c1c88109c7ba0b567df011a8cb13894001"),
    ]
    assert [item["language"] for item in subjects] == ["Java", "Java", "Ruby", "Ruby"]
    assert len({item["repository"].split("/", 1)[0].lower() for item in subjects}) == 4


def test_scanner_routing_is_cell_specific_and_bounded():
    subjects = _payload()["frozen_subjects"]
    assert {item["scanner"] for item in subjects if item["language"] == "Java"} == {
        "qualified-scratch-java-ssrf"
    }
    assert {item["scanner"] for item in subjects if item["language"] == "Ruby"} == {
        "pinned-default-semgrep"
    }
    ceilings = _payload()["resource_ceilings"]
    assert ceilings["logical_scanner_processes"] == 8
    assert ceilings["runtime_import_checks"] == 1
    assert ceilings["repositories"] == 4
    assert ceilings["retrieval_index_builds"] == 4


def test_capacity_rule_retains_all_four_families_and_cap():
    contract = _payload()["aggregate_capacity_contract"]
    assert contract["base"]["by_supported_family"] == {
        "Python": 29,
        "TypeScript": 19,
        "Java": 0,
        "Ruby": 0,
    }
    assert contract["base"]["capped_packet_capacity"] == 39
    assert "sum(min(family_groups,20)) to be at least 40" in contract["capacity_rule"]
    assert "every Python, TypeScript, Java, and Ruby family" in contract["capacity_rule"]


def test_only_github_network_and_zero_live_or_store_activity_are_authorized():
    ceilings = _payload()["resource_ceilings"]
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


def test_receipt_is_pending_and_stops_before_packet_or_provider_use():
    payload = _payload()
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert payload["project_owner_source_review"]["status"] == "approved"
    assert payload["project_owner_source_review"]["execution_authorized_by_review_alone"] is False
    statement = payload["authorization"]["required_statement"]
    assert "packet construction" in statement
    assert "provider calls" in statement
    assert "OPT-010 promotion or closure" in statement
