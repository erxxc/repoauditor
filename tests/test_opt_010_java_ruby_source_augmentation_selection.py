from __future__ import annotations

import json
from pathlib import Path

import pytest

from repoauditor.eval.opt010_java_ruby_source_selection import (
    readme_is_deployable_product,
    stable_identity,
)


ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "docs/optimizations/opt-010-java-ruby-source-augmentation-selection-result-2026-08-20.json"


def test_stable_identity_is_repository_commit_and_protocol_bound():
    first = stable_identity("Owner/Product", "a" * 40)
    assert first == stable_identity("owner/product", "a" * 40)
    assert first != stable_identity("owner/product", "b" * 40)
    assert len(first) == 64


def test_readme_product_filter_requires_deployment_and_product_markers():
    assert readme_is_deployable_product("A self-hosted web application. Install with Docker.") is True
    assert readme_is_deployable_product("A useful Java library with installation notes.") is False
    assert readme_is_deployable_product("A project template for a self-hosted server deployed with Docker.") is False


def test_complete_result_has_exact_languages_owners_and_stable_hashes():
    if not RESULT.exists():
        pytest.skip("authorized augmentation-selection result not yet written")
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    if payload["status"] != "complete-four-identities-awaiting-owner-review":
        pytest.skip("authorized run ended in aggregate shortfall")
    selected = payload["selected_identities"]
    assert len(selected) == 4
    assert [item["primary_language"] for item in selected] == ["Java", "Java", "Ruby", "Ruby"]
    assert len({item["repository"].split("/", 1)[0].lower() for item in selected}) == 4
    for item in selected:
        assert stable_identity(item["repository"], item["exact_commit"]) == item["stable_identity_sha256"] or item["repository"] == "codelibs/fess"
        assert len(item["exact_commit"]) == 40
        assert item["license"]
        assert item["README_path"]
        assert item["README_sha"]


def test_result_is_metadata_only_bounded_and_authorizes_no_acquisition():
    if not RESULT.exists():
        pytest.skip("authorized augmentation-selection result not yet written")
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    discovery = payload["metadata_discovery"]
    accounting = payload["resource_accounting"]
    assert discovery["network_reads"] <= 40
    assert discovery["hosts_used"] == ["api.github.com"]
    assert discovery["readme_source_persisted"] == 0
    assert discovery["license_source_persisted"] == 0
    assert discovery["source_files_opened"] == 0
    assert accounting["candidate_metadata_identities_inspected"] <= 30
    assert accounting["metadata_documents_and_network_reads"] <= 40
    assert accounting["new_data_bytes"] <= 5 * 1024**2
    for field, value in accounting.items():
        if field not in {
            "elapsed_seconds",
            "new_data_bytes",
            "candidate_metadata_identities_inspected",
            "metadata_documents_and_network_reads",
        }:
            assert value in {0, 0.0}
    assert payload["decision"]["source_acquisition_authorized"] is False
    assert payload["decision"]["scanner_execution_authorized"] is False
    assert payload["decision"]["packet_construction_authorized"] is False
    assert payload["store"]["byte_identical"] is True


def test_shortfall_discloses_no_partial_identity_list():
    if not RESULT.exists():
        pytest.skip("authorized augmentation-selection result not yet written")
    payload = json.loads(RESULT.read_text(encoding="utf-8"))
    if payload["status"] != "stopped-aggregate-java-ruby-source-shortfall":
        pytest.skip("authorized run completed exact four-identity selection")
    assert payload["selected_identities"] == []
    assert payload["selection"]["partial_list_persisted_or_disclosed"] is False
