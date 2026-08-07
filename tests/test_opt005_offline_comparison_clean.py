"""The clean offline comparison closes OPT-005 without provider or limit changes."""

import json
from pathlib import Path


REPORT = Path(__file__).resolve().parents[1] / "docs/optimizations/opt-005-offline-comparison-clean-2026-08-07.json"


def test_clean_offline_comparison_is_qualified_and_zero_provider():
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    roles = {item["role"]: item for item in report["observations"]}

    assert report["status"] == "ready"
    assert report["ready"] is True
    assert report["blockers"] == []
    assert report["provider_calls_made"] == 0
    assert report["network_accessed"] is False
    assert report["selected_terminal_runs"] == {
        "lightweight": 105, "independent_pre": 75, "independent_post": 90
    }
    assert all(item["qualified"] for item in roles.values())
    assert all(item["unknown_usage_calls"] == 0 for item in roles.values())
    assert report["configured_per_batch_ceilings"] == {
        "calls": 75, "processed_tokens": 250000
    }
    assert "Retain the current operational ceilings" in report["decision"]
