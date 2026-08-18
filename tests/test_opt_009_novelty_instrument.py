from __future__ import annotations

import json

from repoauditor.eval.novelty_instrument import (
    NEGATIVE_REL,
    POSITIVE_REL,
    _region,
    run_offline_audit,
)


def test_frozen_canary_requests_fit_both_byte_bounds():
    for relative_path in (POSITIVE_REL, NEGATIVE_REL):
        _content, bounds = _region(relative_path)
        assert bounds["region_utf8_bytes"] < 240_000
        assert bounds["request_content_utf8_bytes"] < 320_000
        assert bounds["source_truncated"] is False


def test_offline_audit_is_aggregate_only_and_passes():
    result = run_offline_audit()

    assert result["status"] == "passed"
    assert all(result["checks"].values())
    assert result["retained_accounting"] == {
        "completed_owasp_regions": 12,
        "region_finding_count": 0,
        "persisted_llm_origin_findings": 0,
    }
    assert result["candidate_identities_disclosed"] == 0
    assert result["source_excerpts_persisted"] == 0
    assert result["production_store"]["before_sha256"] == result["production_store"]["after_sha256"]
    assert "primary_file" not in json.dumps(result)
