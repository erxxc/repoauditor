from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-010-supported-primary-augmentation-receipt-2026-08-20.json"


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_receipt_binds_current_inputs_and_instruments():
    payload = _payload()
    for record in payload["frozen_inputs"].values():
        if isinstance(record, dict):
            assert _sha256(ROOT / record["path"]) == record["sha256"]
    for record in payload["frozen_instruments"].values():
        assert _sha256(ROOT / record["path"]) == record["sha256"]


def test_exact_second_supported_primaries_are_frozen():
    subjects = _payload()["protected_augmentation_wave"]["subjects"]
    assert [(item["order"], item["language"]) for item in subjects] == [
        (7, "Python"),
        (8, "TypeScript"),
        (10, "Java"),
        (11, "Ruby"),
    ]
    assert [item["repository"] for item in subjects] == [
        "alexta69/metube",
        "TriliumNext/Trilium",
        "Athou/commafeed",
        "solectrus/solectrus",
    ]
    assert all(len(item["exact_commit"]) == 40 for item in subjects)
    assert all(len(item["stable_identity_sha256"]) == 64 for item in subjects)


def test_semgrep_preflight_and_mapping_precede_scanner_access():
    payload = _payload()
    contract = payload["runtime_and_preflight_contract"]
    requirements = " ".join(contract["requirements"])
    assert contract["semgrep_version"] == "1.170.0"
    assert "mapping byte-for-byte" in requirements
    assert "before any Semgrep-capable process or scanner-artifact access" in requirements
    assert "SEMGREP_LOG_FILE" in requirements
    assert "SEMGREP_VERSION_CACHE_PATH" in requirements
    assert "semgrep.dev" in requirements


def test_aggregate_screen_is_provisional_and_outcome_blind():
    contract = _payload()["aggregate_metadata_feasibility_contract"]
    assert "sum(min(deduplicated_group_count_for_family,20))" in contract["family_feasibility"]
    assert "separately authorized architecture-map" in contract["interpretation"]
    assert "does not freeze a packet" in contract["interpretation"]
    assert "No security advisory" in contract["outcome_blinding"]


def test_resource_and_zero_activity_boundaries_are_exact():
    ceilings = _payload()["resource_ceilings"]
    assert ceilings["repositories"] == 4
    assert ceilings["logical_scanner_processes"] == 12
    assert ceilings["retrieval_index_builds"] == 4
    assert ceilings["maximum_new_data_bytes"] == 15 * 1024**3
    assert ceilings["allowed_network_hosts"] == ["github.com"]
    for field in (
        "network_uploads",
        "provider_calls",
        "provider_reported_tokens",
        "keychain_or_credential_reads",
        "repository_code_executions",
        "dependency_resolutions_or_installations",
        "other_scanner_processes",
        "production_store_reads",
        "production_store_mutations",
        "human_reviews",
        "outcomes_read",
        "assessments",
        "labels",
        "model_training_runs",
        "rescoring_runs",
        "agentic_or_baseline_runs",
        "workspace_branch_or_index_mutations",
        "commits",
        "merges",
        "pushes",
        "lifecycle_changes",
    ):
        assert ceilings[field] == 0


def test_receipt_remains_authorization_pending_and_cannot_close_opt010():
    payload = _payload()
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    statement = payload["authorization"]["required_statement"]
    assert "OPT-010 promotion or closure" in statement
    assert "architecture recovery" in statement
    assert "paired execution" in statement
