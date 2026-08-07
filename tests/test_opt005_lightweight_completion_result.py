"""The terminal lightweight OPT-005 result remains inside its authorization."""

import json
from pathlib import Path


RESULT = (
    Path(__file__).resolve().parents[1]
    / "docs/optimizations/opt-005-lightweight-completion-result-2026-08-07.json"
)


def test_lightweight_completion_result_is_terminal_bounded_and_unprotected():
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    execution = result["execution"]
    ceilings = result["authorized_ceilings"]
    terminal = result["terminal_state"]

    assert result["status"] == "lightweight-queue-complete"
    assert result["external_disclosure_authorized"] is True
    assert execution["completed_batches"] <= ceilings["batches"]
    assert execution["provider_calls"] <= ceilings["provider_calls"]
    assert execution["provider_reported_tokens"] <= ceilings["provider_reported_tokens"]
    assert execution["calculated_cost_usd"] <= ceilings["usd"]
    assert execution["unknown_usage_calls"] == 0
    assert execution["priced_provider_calls"] == execution["provider_calls"]
    assert execution["parent_chain_valid"] is True
    assert execution["protected_snapshot_calls"] == 0
    assert execution["pending_after"] == terminal["lightweight_pending_findings"] == 0
    assert terminal["resolved_findings"] + terminal["unresolved_findings"] == terminal["canonical_findings"]
    assert "remains open" in result["claim_boundary"]["optimization"]
