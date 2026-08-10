"""The OPT-002 bounded review result preserves analyst intent and stays non-mutating."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from repoauditor.eval.independent_review import ALLOWED_DISPOSITIONS


ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "docs/optimizations/opt-002-bounded-review-result-2026-08-10.json"
PLAN = ROOT / "data/artifacts/opt002-independent-packet/review-plan.json"


def _payload() -> dict:
    return json.loads(RESULT.read_text(encoding="utf-8"))


def test_result_covers_the_frozen_packet_once_with_valid_responses():
    payload = _payload()
    plan = json.loads(PLAN.read_text(encoding="utf-8"))
    responses = payload["responses"]

    assert [row["finding_id"] for row in responses] == [
        row["finding_id"] for row in plan["entries"]
    ]
    assert len({row["finding_id"] for row in responses}) == 12
    assert all(row["disposition"] in ALLOWED_DISPOSITIONS for row in responses)
    assert all(row["rationale"].strip() for row in responses)


def test_result_counts_binary_classes_and_preserves_abstention():
    payload = _payload()
    validation = payload["validation"]
    counts = Counter(row["binary_projection"] for row in payload["responses"])

    assert counts == Counter({False: 6, True: 5, "abstain": 1})
    assert validation["decided_labels"] == 11
    assert validation["abstentions"] == 1
    assert validation["minimum_decided_labels_met"] is True
    assert validation["both_classes_present"] is True
    assert validation["abstentions_preserved"] is True


def test_result_records_zero_activity_outside_authorized_review():
    payload = _payload()
    accounting = payload["authorization_accounting"]

    assert accounting["store_byte_identical"] is True
    assert accounting["network_reads"] == 0
    assert accounting["provider_calls"] == 0
    assert accounting["store_mutations"] == 0
    assert accounting["classifier_labels_written"] == 0
    assert all(payload["not_executed"].values())
