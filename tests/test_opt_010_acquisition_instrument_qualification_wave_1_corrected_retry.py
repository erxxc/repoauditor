from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from repoauditor.eval.opt010_acquisition_qualification import (
    PIP_AUDIT_COMMAND,
    SUBJECTS,
    _detector_input_digest,
    _snapshot_digest,
    direct_pin_manifest,
    run_direct_pip_audit,
    verifier_eligibility,
)


ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / (
    "docs/optimizations/"
    "opt-010-prospective-acquisition-instrument-qualification-wave-1-"
    "corrected-retry-result-2026-08-19.json"
)
RUNTIME_RESULT = ROOT / (
    "docs/optimizations/"
    "opt-010-prospective-acquisition-instrument-qualification-wave-1-"
    "runtime-identity-retry-result-2026-08-19.json"
)


def test_subjects_are_the_exact_six_frozen_language_order():
    assert [subject.order for subject in SUBJECTS] == [1, 2, 3, 4, 5, 6]
    assert [subject.language for subject in SUBJECTS] == [
        "Python", "TypeScript", "Go", "Java", "Ruby", "Rust"
    ]
    assert all(len(subject.commit) == 40 for subject in SUBJECTS)


def test_direct_pin_manifest_rejects_resolution_inputs(tmp_path: Path):
    accepted = tmp_path / "accepted.txt"
    accepted.write_text("requests==2.19.1\nFlask==3.0.3 # exact\n")
    assert direct_pin_manifest(accepted) == (True, None)

    for index, value in enumerate((
        "requests>=2\n",
        "-r shared.txt\n",
        "package @ https://example.test/package.whl\n",
        "-e .\n",
        "requests==2.19.1; python_version > '3'\n",
    )):
        rejected = tmp_path / f"rejected-{index}.txt"
        rejected.write_text(value)
        assert direct_pin_manifest(rejected)[0] is False


def test_pip_audit_uses_only_the_exact_no_resolution_invocation(tmp_path: Path):
    manifest = tmp_path / "requirements.txt"
    output = tmp_path / "raw.json"
    manifest.write_text("requests==2.19.1\n")
    completed = type("Completed", (), {
        "returncode": 1,
        "stdout": json.dumps({"dependencies": [{"name": "requests", "vulns": [{"id": "V"}]}]}),
        "stderr": "",
    })()

    with patch(
        "repoauditor.eval.opt010_acquisition_qualification.tool_version",
        return_value="pip-audit 2.10.1",
    ), patch(
        "repoauditor.eval.opt010_acquisition_qualification._run",
        return_value=completed,
    ) as run:
        result = run_direct_pip_audit(manifest, output)

    command = run.call_args.args[0]
    assert command == [
        manifest.as_posix() if item == "$MANIFEST" else item
        for item in PIP_AUDIT_COMMAND
    ]
    assert result["status"] == "complete"
    assert result["finding_count"] == 1
    assert result["dependency_resolution"] is False
    assert result["dependency_installation"] is False


def test_snapshot_and_detector_digests_are_deterministic_and_git_excluded(tmp_path: Path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "ignored").write_text("one")
    (tmp_path / "service.py").write_text("print('ok')\n")
    first_snapshot = _snapshot_digest(tmp_path)
    first_detector = _detector_input_digest(tmp_path)
    (tmp_path / ".git" / "ignored").write_text("two")
    assert _snapshot_digest(tmp_path) == first_snapshot
    assert _detector_input_digest(tmp_path) == first_detector


def test_verifier_eligibility_does_not_infer_mechanisms_from_scanners():
    subjects = [{"language": subject.language} for subject in SUBJECTS]
    result = verifier_eligibility(subjects)

    assert result["language_supported_subjects"] == 4
    assert result["language_unsupported_subjects"] == 2
    assert result["mechanism_vocabulary_resolved_subjects"] == 0
    assert result["fully_eligible_subjects"] == 0


def test_corrected_result_stops_on_functionally_passing_osv_version_drift():
    result = json.loads(RESULT.read_text())
    canaries = {item["scanner"]: item for item in result["canaries"]}

    assert result["status"] == "stopped-preflight-osv-version-drift"
    assert canaries["pip-audit-direct-no-deps"]["functional_status"] == "passed"
    assert canaries["pip-audit-direct-no-deps"]["dependency_resolution"] is False
    assert canaries["osv-scanner"]["expected_version"] == "2.3.8"
    assert canaries["osv-scanner"]["observed_version"] == "2.4.0"
    assert canaries["osv-scanner"]["functional_status"] == "passed"
    assert canaries["osv-scanner"]["identity_status"] == "failed-version-drift"


def test_corrected_result_has_zero_acquisition_store_provider_and_git_activity():
    result = json.loads(RESULT.read_text())
    accounting = result["accounting"]

    assert result["store"]["before_sha256"] == result["store"]["after_sha256"]
    zero_fields = (
        "repositories_materialized",
        "repository_scanners",
        "retrieval_indexes",
        "repository_code_executions",
        "dependency_resolutions",
        "dependency_installations",
        "network_uploads",
        "provider_calls",
        "provider_reported_tokens",
        "provider_cost_usd",
        "production_store_reads",
        "production_store_mutations",
        "assessments",
        "labels",
        "model_training_runs",
        "rescoring_runs",
        "human_finding_reviews",
        "agentic_runs",
        "workspace_branch_or_index_operations",
        "commits",
        "merges",
        "pushes",
        "lifecycle_changes",
    )
    assert all(accounting[field] == 0 for field in zero_fields)
    assert result["decision"]["current_authority_exhausted"] is True


def test_runtime_identity_result_completes_all_six_exact_subjects():
    result = json.loads(RUNTIME_RESULT.read_text())

    assert result["status"] == "complete-six-subject-offline-instrument-qualification"
    assert [subject["order"] for subject in result["subjects"]] == [1, 2, 3, 4, 5, 6]
    assert all(subject["terminal_state"] == "completed" for subject in result["subjects"])
    assert all(len(subject["snapshot_sha256"]) == 64 for subject in result["subjects"])
    assert all(len(subject["detector_input_sha256"]) == 64 for subject in result["subjects"])
    assert all(len(subject["retrieval_index_sha256"]) == 64 for subject in result["subjects"])
    assert all(subject["architecture_map_sha256"].startswith("pending") for subject in result["subjects"])


def test_runtime_identity_result_has_complete_scanner_and_retrieval_inventory():
    result = json.loads(RUNTIME_RESULT.read_text())
    inventory = result["aggregate_inventory"]

    assert inventory["subjects_completed"] == 6
    assert inventory["snapshot_files"] == 14600
    assert inventory["detector_source_files"] == inventory["retrieval_source_files"] == 10369
    assert inventory["retrieval_indexed_functions"] == 132164
    assert inventory["scanner_executions"] == 30
    assert inventory["scanner_findings"] == 918
    assert inventory["candidate_or_finding_identities_disclosed"] == 0
    assert inventory["source_paths_symbols_or_excerpts_disclosed"] == 0


def test_runtime_identity_result_preserves_partial_gate_interpretation():
    result = json.loads(RUNTIME_RESULT.read_text())
    eligibility = result["verifier_eligibility"]
    decision = result["decision"]

    assert eligibility["language_supported_subjects"] == 4
    assert eligibility["language_unsupported_subjects"] == 2
    assert eligibility["mechanism_vocabulary_unresolved_subjects"] == 6
    assert eligibility["fully_eligible_subjects"] == 0
    assert decision["G02"].startswith("partial")
    assert decision["G05"].startswith("partial")
    assert decision["G07"].startswith("partial")
    assert decision["G03b"] == "not-authorized"
    assert decision["OPT_010_status"] == "open-deferred"


def test_runtime_identity_result_keeps_store_provider_review_and_workspace_git_zero():
    result = json.loads(RUNTIME_RESULT.read_text())
    accounting = result["resource_accounting"]

    assert result["store"]["before_sha256"] == result["store"]["after_sha256"]
    assert accounting["new_logical_scanner_processes"] == 35
    assert accounting["cumulative_logical_scanner_processes"] == 44
    assert accounting["repositories_materialized"] == 6
    assert accounting["retrieval_indexes"] == 6
    zero_fields = (
        "repository_code_executions", "dependency_resolutions", "dependency_installations",
        "network_uploads", "provider_calls", "provider_reported_tokens",
        "provider_cost_usd", "production_store_reads", "production_store_mutations",
        "assessments", "labels", "model_training_runs", "rescoring_runs",
        "human_finding_reviews", "agentic_runs", "workspace_branch_or_index_operations",
        "commits", "merges", "pushes", "lifecycle_changes",
    )
    assert all(accounting[field] == 0 for field in zero_fields)
