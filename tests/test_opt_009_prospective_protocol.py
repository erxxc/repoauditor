"""OPT-009 freezes a hybrid prospective comparison before source selection."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "docs/optimizations/opt-009-prospective-hybrid-protocol-2026-08-12.json"
RECEIPT = ROOT / "docs/optimizations/opt-009-prospective-source-selection-receipt-2026-08-12.json"
RESULT = ROOT / "docs/optimizations/opt-009-prospective-source-selection-result-2026-08-12.json"
DETECTION_RECEIPT = ROOT / "docs/optimizations/opt-009-prospective-detection-wave-1-receipt-2026-08-12.json"


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_protocol_binds_negative_audit_and_separates_hybrid_roles():
    payload = _load(PROTOCOL)
    audit = payload["completed_eligibility_audit"]
    audit_path = PROTOCOL.parent / audit["path"]
    assert hashlib.sha256(audit_path.read_bytes()).hexdigest() == audit["sha256"]
    assert audit["observed_llm_origin_records"] == 63
    assert audit["evidence_eligible_records"] == 0
    roles = payload["hybrid_roles"]
    assert "held-out outcome evidence" in roles["existing_protocol_development_corpus"]["forbidden_uses"]
    assert roles["prospective_evidence_corpus"]["minimum_decided_issue_groups"] == 48
    assert roles["prospective_evidence_corpus"]["minimum_independent_evaluation_families"] == 8


def test_primary_comparison_is_fixed_before_outcomes():
    payload = _load(PROTOCOL)
    comparison = payload["frozen_comparison"]
    novelty = payload["novelty_definition"]
    assert comparison["fixed_investigation_budget_per_family"] == 3
    assert comparison["primary_outcome"] == "Project-owner disposition confirmed_actionable."
    assert comparison["baseline_order"].startswith("Severity ordinal descending")
    assert comparison["novelty_order"].startswith("Novelty score descending")
    assert novelty["reference"]["outcomes_read"] is False
    assert "severity or confidence" in novelty["forbidden_fields"]
    assert "Primary benefit uses continuous novelty rank" in novelty["threshold_policy"]


def test_data_sufficiency_does_not_silently_establish_benefit():
    gates = _load(PROTOCOL)["gates"]
    assert gates["data_sufficiency"]["all_required"] is True
    assert "does not establish benefit" in gates["data_sufficiency"]["effect"]
    assert gates["held_out_benefit"]["all_required"] is True
    assert any("at least three more" in item for item in gates["held_out_benefit"]["conditions"])
    assert any("95% interval lower bound" in item for item in gates["held_out_benefit"]["conditions"])


def test_prompt_files_and_primary_lens_are_digest_frozen():
    detection = _load(PROTOCOL)["frozen_detection_identity"]
    records = [detection["primary_evaluation_lens"], *detection["observational_lenses"]]
    assert detection["primary_evaluation_lens"]["name"] == "owasp"
    for record in records:
        prompt = (PROTOCOL.parent / record["prompt_path"]).resolve()
        assert hashlib.sha256(prompt.read_bytes()).hexdigest() == record["prompt_sha256"]
    assert "Only OWASP-lens findings enter the primary comparison" in detection["interpretation"]


def test_source_selection_receipt_is_metadata_only_and_pending():
    payload = _load(RECEIPT)
    protocol_path = RECEIPT.parent / payload["protocol"]["path"]
    assert hashlib.sha256(protocol_path.read_bytes()).hexdigest() == payload["protocol"]["sha256"]
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert payload["resource_ceilings"] == {
        "selected_primary_repositories": 8,
        "selected_reserve_repositories": 4,
        "maximum_elapsed_minutes": 30,
        "maximum_new_data_bytes": 5242880,
        "network_hosts": ["github.com", "api.github.com"],
        "uploads": 0,
        "provider_calls": 0,
        "provider_reported_tokens": 0,
        "provider_cost_usd": 0.0,
        "store_mutations": 0,
        "source_code_files_rendered": 0,
        "maximum_readme_and_license_documents": 24,
        "human_reviews": 0,
        "assessments_written": 0,
        "labels_written": 0,
        "models_trained": 0,
    }
    assert "It may not clone" in payload["selection_contract"]["no_materialization"]
    assert "Security advisories" in payload["authorization"]["required_statement"]


def test_source_selection_result_binds_receipt_and_exact_balanced_roles():
    payload = _load(RESULT)
    for key in ("execution_receipt", "protocol"):
        record = payload[key]
        path = RESULT.parent / record["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == record["sha256"]
    sources = payload["selected_sources"]
    assert len(sources) == 12
    assert [row["order"] for row in sources if row["role"] == "primary"] == list(range(1, 9))
    assert [row["order"] for row in sources if row["role"] == "reserve"] == list(range(1, 5))
    assert len({row["evaluation_family"] for row in sources}) == 12
    assert len(set(payload["selection_summary"]["primary_ancestries"])) >= 3


def test_selected_sources_are_exact_active_and_identity_frozen():
    sources = _load(RESULT)["selected_sources"]
    for row in sources:
        assert row["fork"] is row["archived"] is row["disabled"] is False
        assert len(row["commit"]) == 40
        identity = f'{row["url"]}@{row["commit"]}'.encode()
        assert hashlib.sha256(identity).hexdigest() == row["source_identity_sha256"]
        assert row["selection_basis"]
        assert row["readme_product_evidence"]


def test_selection_result_stops_before_source_or_outcome_activity():
    payload = _load(RESULT)
    accounting = payload["resource_accounting"]
    assert payload["preconditions"]["store_byte_identical"] is True
    assert payload["network_accounting"]["observed_hosts"] == ["github.com", "api.github.com"]
    assert accounting["repository_materializations"] == 0
    assert accounting["source_code_files_rendered"] == 0
    assert accounting["scanners_started"] == 0
    assert accounting["store_mutations"] == 0
    assert accounting["candidate_findings_generated"] == 0
    assert accounting["rankings_generated"] == 0
    assert accounting["provider_calls"] == 0
    assert accounting["human_finding_reviews"] == 0
    assert accounting["assessments_written"] == 0
    assert accounting["labels_written"] == 0
    assert accounting["models_trained"] == 0
    assert payload["disposition"]["acquisition_authorized"] is False


def test_detection_wave_receipt_stages_only_first_two_primaries():
    payload = _load(DETECTION_RECEIPT)
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert [row["repository"] for row in payload["activated_sources"]] == [
        "go-vikunja/vikunja",
        "miniflux/v2",
    ]
    assert all(len(row["commit"]) == 40 for row in payload["activated_sources"])
    assert payload["provider_and_detection_identity"]["active_lenses"] == ["owasp"]
    assert payload["provider_and_detection_identity"]["falsification_calls"] == 0
    assert payload["provider_and_detection_identity"]["normalization_calls"] == 0


def test_detection_wave_binds_source_result_protocol_and_code():
    payload = _load(DETECTION_RECEIPT)
    for key in ("protocol", "source_selection_result"):
        record = payload[key]
        path = DETECTION_RECEIPT.parent / record["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == record["sha256"]
    identity = payload["provider_and_detection_identity"]
    for record in (identity["architecture_prompt"], identity["primary_lens"]):
        for path_key, digest_key in (
            ("implementation_path", "implementation_sha256"),
            ("prompt_path", "prompt_sha256"),
            ("prompt_security_path", "prompt_security_sha256"),
        ):
            if path_key in record:
                path = (DETECTION_RECEIPT.parent / record[path_key]).resolve()
                assert hashlib.sha256(path.read_bytes()).hexdigest() == record[digest_key]


def test_detection_wave_has_bounded_provider_transfer_and_cost():
    payload = _load(DETECTION_RECEIPT)
    ceilings = payload["resource_ceilings"]
    assert ceilings["repositories_materialized"] == 2
    assert ceilings["network_hosts"] == [
        "github.com", "pypi.org", "api.osv.dev", "osv.dev", "api.anthropic.com"
    ]
    assert ceilings["provider_calls_total"] == 150
    assert ceilings["provider_reported_tokens_total"] == 500000
    assert ceilings["provider_cost_usd"] == 12.5
    assert ceilings["human_reviews"] == 0
    assert ceilings["assessments_written"] == 0
    assert ceilings["labels_written"] == 0
    assert ceilings["models_trained"] == 0
    assert ceilings["novelty_scores_or_ranks"] == 0
    assert "bounded source excerpts" in payload["provider_and_detection_identity"]["public_data_transfer"]


def test_detection_wave_fails_closed_before_reserves_or_review():
    payload = _load(DETECTION_RECEIPT)
    capacity = payload["eligibility_capacity_measurement"]
    assert capacity["minimum_groups_per_family"] == 8
    assert capacity["aggregate_only"] is True
    assert capacity["candidate_identity_disclosure"] is False
    assert "requires a new receipt" in capacity["capacity_shortfall"]
    required = payload["authorization"]["required_statement"]
    assert "Reserve activation" in required
    assert "candidate identity disclosure" in required
    assert "$12.50" in required
