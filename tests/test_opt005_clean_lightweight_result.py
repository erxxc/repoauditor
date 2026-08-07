"""The replacement lightweight observation is clean, terminal, and bounded."""

import json
from pathlib import Path


RESULT = Path(__file__).resolve().parents[1] / "docs/optimizations/opt-005-clean-lightweight-result-2026-08-07.json"


def test_clean_lightweight_result_satisfies_isolation_and_usage_contracts():
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    isolation = result["isolation"]
    execution = result["execution"]
    ceilings = result["authorized_ceilings"]

    assert result["status"] == "clean-lightweight-terminal"
    assert isolation["root_parent_run_id"] is None
    assert isolation["new_repository_identity"] is True
    assert isolation["detect_completed_calls"] == 18
    assert isolation["detect_reused_completed_calls"] == 0
    assert isolation["parent_chain_valid"] is True
    assert execution["provider_calls"] <= ceilings["provider_calls"]
    assert execution["provider_reported_tokens"] <= ceilings["provider_reported_tokens"]
    assert execution["calculated_cost_usd"] <= ceilings["usd"]
    assert execution["unknown_usage_calls"] == 0
    assert execution["pending_after"] == result["terminal_state"]["deferred_findings"] == 0
    assert "eligible" in result["claim_boundary"]["qualification"]
    assert "not run" in result["claim_boundary"]["offline"]
