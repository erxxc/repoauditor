from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / (
    "docs/optimizations/"
    "opt-010-prospective-acquisition-instrument-qualification-wave-1-"
    "result-2026-08-19.json"
)


def _payload() -> dict:
    return json.loads(RESULT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_result_binds_the_authorized_receipt_and_receipt_test():
    evidence = _payload()["execution_evidence"]

    assert _sha256(ROOT / evidence["receipt"]["path"]) == evidence["receipt"]["sha256"]
    assert evidence["receipt_test"]["sha256"] == (
        "662123111f9a9ff7542dbc940a0a0c1944f3627bb8043a9b8356ccc4f7c7e586"
    )
    assert evidence["receipt_test"]["passed"] == 6
    assert evidence["receipt_test"]["failed"] == 0


def test_runtime_and_retained_canary_artifacts_are_digest_bound():
    payload = _payload()
    artifact_root = ROOT / payload["execution_evidence"]["artifact_directory"]

    version_cache = payload["runtime_preflight"]["semgrep_version_cache"]
    assert _sha256(ROOT / version_cache["path"]) == version_cache["sha256"]

    for item in payload["canaries"]:
        if "artifact_sha256" not in item:
            continue
        path = artifact_root / f"canary-{item['scanner']}.json"
        assert _sha256(path) == item["artifact_sha256"]


def test_preflight_stopped_at_pip_audit_before_osv_or_acquisition():
    payload = _payload()
    canaries = {item["scanner"]: item for item in payload["canaries"]}

    assert payload["status"] == "stopped-preflight-pip-audit-failed"
    assert canaries["semgrep"]["status"] == "passed"
    assert canaries["semgrep-supplemental"]["status"] == "passed"
    assert canaries["gitleaks"]["status"] == "passed"
    assert canaries["pip-audit"]["status"] == "failed"
    assert canaries["osv-scanner"]["status"].startswith("not-attempted")
    assert payload["stop"]["retry_attempted"] is False
    assert payload["accounting"]["repositories_materialized"] == 0
    assert payload["accounting"]["retrieval_index_builds"] == 0


def test_store_and_all_prohibited_activity_remain_zero():
    payload = _payload()
    store = payload["store"]
    accounting = payload["accounting"]

    assert store["before_sha256"] == store["after_sha256"]
    assert store["byte_identical"] is True
    zero_fields = (
        "repositories_materialized",
        "exact_commit_resolutions",
        "repository_code_executions",
        "dependency_installations",
        "logical_repository_scanners_attempted",
        "retrieval_index_builds",
        "provider_calls",
        "provider_reported_tokens",
        "provider_cost_usd",
        "network_uploads",
        "production_store_reads",
        "production_store_mutations",
        "schema_migrations",
        "assessments_written",
        "labels_written",
        "model_training_runs",
        "rescoring_runs",
        "human_finding_reviews",
        "agentic_falsification_runs",
        "branch_or_index_operations",
        "source_commits",
        "merge_commits",
        "remote_pushes",
        "lifecycle_changes",
    )
    assert all(accounting[field] == 0 for field in zero_fields)


def test_result_does_not_overstate_gate_or_lifecycle_progress():
    decision = _payload()["decision"]

    assert decision["wave_one_complete"] is False
    assert decision["subject_terminal_observations"] == 0
    assert decision["G02"] == "unchanged-partial"
    assert decision["G05"] == "unchanged-partial"
    assert decision["G07"] == "unchanged-partial"
    assert decision["OPT_010_status"] == "open-deferred"
    assert decision["current_authority_exhausted"] is True
