"""OPT-002 reconciliation preserves rows and removes duplicate statistical weight."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESULT = (
    ROOT
    / "docs/optimizations/opt-002-duplicate-reconciliation-2026-08-07.json"
)


def _result() -> dict:
    return json.loads(RESULT.read_text(encoding="utf-8"))


def test_reconciliation_is_exact_family_identity_without_deletion():
    payload = _result()

    assert payload["decision"]["identity"] == [
        "evaluation_family",
        "rule_id",
        "finding_fingerprint",
    ]
    assert payload["decision"]["overrides"] == {
        "snapshot": "uat_lightweight_app",
        "snapshot-884a968b": "uat_lightweight_app",
    }
    assert payload["implementation"]["automatic_deletion"] is False
    assert payload["implementation"]["historical_rewrite"] is False
    assert payload["decision"]["conflict_policy"].startswith("Fail closed")


def test_live_store_dry_run_restores_frozen_effective_corpus():
    observed = _result()["read_only_live_store_verification"]

    assert observed["raw_label_rows_after"] == 118
    assert observed["effective_training_rows_after"] == 111
    assert observed["effective_source_counts_after"] == {
        "manual": 104,
        "derived_falsify": 7,
    }
    assert observed["effective_grouped_holdout_families"] == 15
    assert observed["dry_run_selected_model"] == "xgboost"
    assert observed["store_mutations_during_verification"] == 0


def test_reconciliation_authorizes_no_continuation_or_provider_use():
    excluded = set(_result()["authorization_boundary"]["not_authorized"])

    assert "rerun Documenso triage" in excluded
    assert "start Lobsters" in excluded
    assert "provider calls" in excluded
    assert "human review" in excluded
    assert "gate promotion" in excluded
