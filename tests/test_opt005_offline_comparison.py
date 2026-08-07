"""The offline comparison preserves unknown usage as a calibration blocker."""

import json
from pathlib import Path


REPORT = Path(__file__).resolve().parents[1] / "docs/optimizations/opt-005-offline-comparison-2026-08-07.json"


def test_offline_comparison_is_zero_provider_and_fail_closed():
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    roles = {item["role"]: item for item in report["observations"]}

    assert report["status"] == "not-ready"
    assert report["ready"] is False
    assert report["provider_calls_made"] == 0
    assert report["network_accessed"] is False
    assert report["selected_terminal_runs"] == {"lightweight": 61, "independent_pre": 75, "independent_post": 90}
    assert roles["lightweight"]["unknown_usage_calls"] == 2
    assert roles["lightweight"]["qualified"] is False
    assert roles["independent_pre"]["qualified"] is True
    assert roles["independent_post"]["qualified"] is True
    assert "Keep OPT-005 open" in report["decision"]
