"""OPT-011 closes only with aggregate semantics and immutable history."""

import json
from pathlib import Path


RESULT = Path(__file__).resolve().parents[1] / "docs/optimizations/opt-011-implementation-result-2026-08-07.json"


def test_opt011_result_closes_at_the_approved_claim_boundary():
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    invariants = result["invariants"]

    assert result["status"] == "implemented"
    assert result["methodology_version"] == "organization_all_event_v1"
    assert invariants["organization_frequency_streams"] == 1
    assert invariants["base_rate_changes_with_finding_count"] is False
    assert invariants["finding_validity_allocates_frequency"] is False
    assert invariants["finding_exposure_allocates_frequency"] is False
    assert invariants["scenario_attribution_available"] is False
    assert invariants["remediation_delta_available"] is False
    assert result["persistence"]["historical_rows_mutated"] is False
    assert "OPT-014 remains data-gated" in result["next_gate"]
