from __future__ import annotations

from repoauditor.eval.novelty_instrument import (
    NEGATIVE_REL,
    POSITIVE_REL,
    _region,
)


def test_frozen_canary_requests_fit_both_byte_bounds():
    for relative_path in (POSITIVE_REL, NEGATIVE_REL):
        _content, bounds = _region(relative_path)
        assert bounds["region_utf8_bytes"] < 240_000
        assert bounds["request_content_utf8_bytes"] < 320_000
        assert bounds["source_truncated"] is False


def test_historical_offline_audit_is_not_rerun_against_extended_ensemble():
    from pathlib import Path
    import json

    result = json.loads((
        Path(__file__).parents[1]
        / "docs/optimizations/opt-009-instrument-qualification-result-2026-08-13.json"
    ).read_text(encoding="utf-8"))
    assert result["offline_audit"]["status"] == "passed"
    assert result["offline_audit"]["completed_owasp_regions"] == 12
    assert result["offline_audit"]["persisted_llm_origin_findings"] == 0
