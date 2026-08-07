"""The second OPT-005 single batch remains within its exact authorization."""

import json
from pathlib import Path


RESULT = (
    Path(__file__).resolve().parents[1]
    / "docs/optimizations/opt-005-single-batch-2-result-2026-08-07.json"
)


def test_single_batch_2_result_is_bounded_and_excludes_protected_snapshots():
    result = json.loads(RESULT.read_text(encoding="utf-8"))
    execution = result["execution"]
    ceilings = result["authorized_ceilings"]

    assert result["status"] == "single-batch-2-complete"
    assert result["external_disclosure_authorized"] is True
    assert execution["completed_batches"] == ceilings["batches"] == 1
    assert execution["provider_calls"] <= ceilings["provider_calls"]
    assert execution["provider_reported_tokens"] <= ceilings["provider_reported_tokens"]
    assert execution["calculated_cost_usd"] <= ceilings["usd"]
    assert execution["unknown_usage_calls"] == 0
    assert execution["protected_snapshot_calls"] == 0
    assert result["residual_queue"]["pending_findings"] == 46
    assert result["residual_queue"]["conservative_issue_groups"] == 42
