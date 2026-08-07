"""The protected pre-fix continuation reaches a terminal bounded observation."""

import json
from pathlib import Path


RESULT = (
    Path(__file__).resolve().parents[1]
    / "docs/optimizations/opt-005-protected-pre-continuation-result-2026-08-07.json"
)


def test_protected_pre_continuation_result_is_terminal_and_bounded():
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    execution = result["continuation_execution"]
    ceilings = result["authorized_ceilings"]
    chain = result["complete_logical_scan"]

    assert result["status"] == "protected-pre-terminal"
    assert execution["completed_batches"] == ceilings["batches"] == 11
    assert execution["provider_calls"] <= ceilings["provider_calls"]
    assert execution["provider_reported_tokens"] <= ceilings["provider_reported_tokens"]
    assert execution["calculated_cost_usd"] <= ceilings["usd"]
    assert execution["unknown_usage_calls"] == 0
    assert execution["pending_after"] == chain["deferred_findings"] == 0
    assert chain["terminal_pipeline_run_id"] == 75
    assert chain["all_runs_completed"] is True
    assert chain["parent_chain_valid"] is True
    assert chain["unknown_usage_calls"] == 0
    assert chain["resolved_findings"] + chain["unresolved_findings"] == chain["canonical_findings"]
    assert "not inspected" in result["claim_boundary"]["post_fix"]
