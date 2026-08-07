"""OPT-002 primary execution stays exact-commit and zero-provider."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = (
    ROOT
    / "docs/optimizations/opt-002-primary-execution-receipt-2026-08-07.json"
)


def _receipt() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def test_receipt_is_pending_and_limited_to_frozen_primaries():
    payload = _receipt()

    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert [source["repo_id"] for source in payload["frozen_sources"]] == [
        "opt002-documenso",
        "opt002-lobsters",
    ]
    assert payload["resource_ceilings"]["repositories"] == 2
    assert "reserve" in payload["scope"]


def test_every_ingest_is_exact_and_every_detect_is_deterministic_only():
    commands = _receipt()["commands_in_order"]
    ingest = [command for command in commands if " repoauditor ingest " in command]
    detect = [command for command in commands if " repoauditor detect " in command]

    assert len(ingest) == 2
    assert all("--repo-id opt002-" in command for command in ingest)
    assert all("--expected-commit" in command for command in ingest)
    assert len(detect) == 2
    assert all(command.endswith("--deterministic-only") for command in detect)


def test_receipt_allows_no_provider_or_review_activity():
    payload = _receipt()
    ceilings = payload["resource_ceilings"]
    controls = payload["zero_provider_controls"]

    assert ceilings["provider_calls"] == 0
    assert ceilings["provider_reported_tokens"] == 0
    assert ceilings["provider_cost_usd"] == 0
    assert ceilings["network_uploads"] == 0
    assert controls["provider_client_calls_allowed"] == 0
    assert controls["map_stage"] == "not run"
    assert payload["result_contract"]["automatic_labels"] is False
    assert payload["result_contract"]["human_review"] is False
    assert payload["result_contract"]["optimization_status_change"] is False
