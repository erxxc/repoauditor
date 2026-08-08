"""OPT-002 continuation is conditional, exact-identity, and zero-provider."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = (
    ROOT
    / "docs/optimizations/opt-002-zero-provider-continuation-receipt-2026-08-07.json"
)


def _receipt() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def test_continuation_is_pending_and_documenso_reuses_frozen_evidence():
    payload = _receipt()

    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert payload["retained_documenso"]["allowed_operation"].startswith("triage only")
    assert payload["retained_documenso"]["sarif_sha256"] == (
        "aab592fd429b94397b2fd7a2c69dfa781af2332378a15156e1724b2818bcd69f"
    )
    commands = payload["commands_in_order"]
    assert not any("ingest" in command and "documenso" in command for command in commands)
    assert not any(
        " repoauditor detect opt002-documenso " in command for command in commands
    )


def test_lobsters_is_exact_commit_and_conditioned_on_documenso_identity():
    payload = _receipt()
    commands = payload["commands_in_order"]
    ingest = next(command for command in commands if " repoauditor ingest " in command)
    detect = next(command for command in commands if " repoauditor detect " in command)

    assert payload["frozen_lobsters"]["commit"] in ingest
    assert "--repo-id opt002-lobsters" in ingest
    assert "--expected-commit" in ingest
    assert detect.endswith("--deterministic-only")
    assert "Only if its complete scoring identity matches" in payload["scope"]


def test_continuation_has_absolute_zero_provider_boundary():
    payload = _receipt()
    ceilings = payload["resource_ceilings"]
    controls = payload["zero_provider_controls"]

    assert ceilings["provider_calls"] == 0
    assert ceilings["provider_reported_tokens"] == 0
    assert ceilings["provider_cost_usd"] == 0
    assert ceilings["network_uploads"] == 0
    assert controls["provider_client_calls_allowed"] == 0
    assert controls["model_usage_rows_before"] == 1473
    assert controls["model_usage_rows_after_required"] == 1473
    assert payload["result_contract"]["automatic_labels"] is False
    assert payload["result_contract"]["human_review"] is False
    assert payload["result_contract"]["optimization_status_change"] is False
