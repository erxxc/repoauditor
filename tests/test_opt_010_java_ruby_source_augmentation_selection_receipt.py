from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-010-java-ruby-source-augmentation-selection-receipt-2026-08-20.json"


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_receipt_binds_current_negative_screen_and_lifecycle_inputs():
    payload = _payload()
    for name, record in payload["frozen_inputs"].items():
        if isinstance(record, dict):
            if name == "optimization_status":
                assert len(record["sha256"]) == 64
            else:
                assert _sha256(ROOT / record["path"]) == record["sha256"]


def test_fixed_reserve_is_exact_untouched_java_nomination():
    reserve = _payload()["frozen_java_reserve_nomination"]
    assert reserve["repository"] == "codelibs/fess"
    assert reserve["exact_commit"] == "41f138b5b91af26413ae6cab05bb6acffa6611df"
    assert reserve["stable_identity_sha256"] == "9f6e322f1bb116d30ef5c417dbe99bf3aaa1ef3ba5ec296a9476c7d3236bd17e"
    assert reserve["primary_language"] == "Java"
    assert reserve["acquisition_authorized"] is False


def test_queries_are_exact_bounded_java_and_ruby_metadata_only():
    contract = _payload()["metadata_discovery_contract"]
    queries = contract["queries"]
    assert [item["language"] for item in queries] == ["Java", "Ruby"]
    assert all(item["candidate_limit"] == 15 for item in queries)
    for item in queries:
        query = item["q"]
        assert "topic:self-hosted" in query
        assert "fork:false" in query and "archived:false" in query
        assert "stars:>=100" in query
        assert "created:<=2024-08-20" in query
        assert "pushed:>=2025-08-20" in query
        assert f"language:{item['language']}" in query
    assert contract["candidate_pool_maximum"] == 30
    assert contract["outcome_blind"] is True


def test_selection_requires_exactly_two_per_language_and_four_owners():
    required = _payload()["metadata_discovery_contract"]["required_result"]
    assert required == {
        "selected_identities": 4,
        "Java": 2,
        "Ruby": 2,
        "fixed_reserve_identities": 1,
        "new_metadata_selected_identities": 3,
        "distinct_owners": 4,
    }
    shortfall = _payload()["metadata_discovery_contract"]["shortfall_rule"]
    assert "disclose no partial new identity list" in shortfall


def test_resource_boundaries_allow_only_github_metadata_reads():
    ceilings = _payload()["resource_ceilings"]
    assert ceilings["maximum_elapsed_minutes"] == 30
    assert ceilings["maximum_new_data_bytes"] == 5 * 1024**2
    assert ceilings["candidate_metadata_identities_inspected"] == 30
    assert ceilings["metadata_documents_and_network_reads"] == 40
    assert ceilings["allowed_hosts"] == ["github.com", "api.github.com"]
    assert ceilings["selected_identities"] == 4
    for field, value in ceilings.items():
        if field not in {
            "maximum_elapsed_minutes",
            "maximum_new_data_bytes",
            "candidate_metadata_identities_inspected",
            "metadata_documents_and_network_reads",
            "allowed_hosts",
            "selected_identities",
        }:
            assert value in {0, 0.0}


def test_receipt_is_pending_and_authorizes_no_acquisition_or_scanning():
    payload = _payload()
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    statement = payload["authorization"]["required_statement"]
    assert "source acquisition or scanning" in statement
    assert "disclose no partial new list" in statement
    assert "OPT-010 promotion or closure" in statement
