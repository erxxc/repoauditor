"""The protected pre-fix attempt stops exactly at its authorized batch cap."""

import json
from pathlib import Path


RESULT = (
    Path(__file__).resolve().parents[1]
    / "docs/optimizations/opt-005-protected-pre-result-2026-08-07.json"
)


def test_protected_pre_result_is_bounded_nonterminal_and_pre_only():
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    execution = result["execution"]
    ceilings = result["authorized_ceilings"]

    assert result["status"] == "protected-pre-batch-cap-reached"
    assert result["external_disclosure_authorized"] is True
    assert execution["completed_batches"] == ceilings["linked_batches"] == 3
    assert execution["provider_calls"] <= ceilings["provider_calls"]
    assert execution["provider_reported_tokens"] <= ceilings["provider_reported_tokens"]
    assert execution["calculated_cost_usd"] <= ceilings["usd"]
    assert execution["unknown_usage_calls"] == 0
    assert execution["priced_provider_calls"] == execution["provider_calls"]
    assert execution["deferred_after"] == 44
    assert execution["protected_post_calls"] == 0
    assert result["outcome"]["terminal"] is False
    assert "not a qualifying terminal" in result["claim_boundary"]["pre_fix"]
