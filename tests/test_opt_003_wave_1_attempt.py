"""OPT-003 wave one stops before acquisition on failed scanner health."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ATTEMPT = ROOT / "docs/optimizations/opt-003-wave-1-attempt-2026-08-10.json"


def test_attempt_stops_before_all_sources_and_outcomes():
    payload = json.loads(ATTEMPT.read_text(encoding="utf-8"))
    assert payload["status"] == "stopped-before-acquisition"
    assert payload["stop"]["passed"] is False
    assert payload["accounting"]["repositories_materialized"] == 0
    assert payload["accounting"]["predictions_persisted"] == 0
    assert payload["accounting"]["assessments_written"] == 0
    assert payload["accounting"]["labels_written"] == 0
    assert all(payload["not_executed"].values())


def test_attempt_preserves_store_and_discloses_boundary_breach():
    payload = json.loads(ATTEMPT.read_text(encoding="utf-8"))
    accounting = payload["accounting"]
    assert accounting["initial_store_sha256"] == accounting["final_store_sha256"]
    assert accounting["store_byte_identical"] is True
    assert accounting["ceiling_breaches"]
    assert "unsupported-host" in payload["stop"]["network_boundary_incident"]
    assert payload["disposition"]["model_reuse"].startswith("not authorized")
