"""OPT-003 wave two freezes a new model and three outcome-blind families."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-003-wave-2-prediction-receipt-2026-08-11.json"


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_receipt_binds_protocol_and_completed_wave_one_import():
    payload = _payload()
    protocol = ROOT / "docs/optimizations" / payload["protocol"]["path"]
    prior = ROOT / "docs/optimizations" / payload["prior_gate_evidence"]["path"]

    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert _sha256(protocol) == payload["protocol"]["sha256"]
    assert _sha256(prior) == payload["prior_gate_evidence"]["sha256"]
    assert payload["prior_gate_evidence"]["remaining_decided_label_shortfall"] == 13
    assert payload["prior_gate_evidence"]["remaining_evaluation_family_shortfall"] == 3


def test_receipt_freezes_post_import_training_identity_before_acquisition():
    payload = _payload()
    cutoff = payload["training_cutoff"]
    sequence = payload["execution_sequence"]

    assert cutoff["initial_store_sha256"] == "a8f06e0b7e5201449711eaa71f429bb79f68ab638f9072f259f04cd93ea5e61d"
    assert cutoff["effective_family_distinct_labels"] == 138
    assert cutoff["effective_positive"] == 47
    assert cutoff["effective_negative"] == 91
    assert cutoff["effective_evaluation_families"] == 21
    assert len(cutoff["effective_label_identity_sha256"]) == 64
    train = next(index for index, item in enumerate(sequence) if "train and persist" in item)
    materialize = next(index for index, item in enumerate(sequence) if "materialize" in item and "Resolve each remote" in item)
    assert train < materialize


def test_receipt_freezes_three_exact_new_families_without_security_inputs():
    payload = _payload()
    sources = payload["frozen_sources"]
    forbidden = " ".join(payload["source_selection_contract"]["forbidden_inputs"])

    assert len(sources) == 3
    assert len({item["repo_id"] for item in sources}) == 3
    assert len({item["evaluation_family"] for item in sources}) == 3
    assert len({item["commit"] for item in sources}) == 3
    assert all(len(item["commit"]) == 40 for item in sources)
    assert all(item["selection_basis"] for item in sources)
    assert "security findings" in forbidden
    assert "scanner output" in forbidden
    assert "scores" in forbidden
    assert "target paths" in forbidden


def test_receipt_separates_preflights_and_allows_only_named_hosts():
    payload = _payload()
    preflight = payload["separated_preflight"]
    ceilings = payload["resource_ceilings"]

    assert "--scanner semgrep" in preflight["offline_command"]
    assert "--scanner semgrep-supplemental" in preflight["offline_command"]
    assert "--scanner gitleaks" in preflight["offline_command"]
    assert "pip-audit" not in preflight["offline_command"]
    assert "osv-scanner" not in preflight["offline_command"]
    assert "--scanner pip-audit" in preflight["advisory_command"]
    assert "--scanner osv-scanner" in preflight["advisory_command"]
    assert set(ceilings["allowed_network_hosts"]) == {
        "github.com", "pypi.org", "api.osv.dev", "osv.dev",
    }


def test_receipt_requires_packet_capacity_but_stops_before_outcomes():
    payload = _payload()
    inventory = payload["prediction_inventory_contract"]
    ceilings = payload["resource_ceilings"]
    excluded = " ".join(payload["result_boundary"]["not_authorized"])

    assert inventory["minimum_eligible_identities_per_family"] == 6
    assert inventory["minimum_total_eligible_identities"] == 18
    assert "no decided-label count is guaranteed" in inventory["gate_target"]
    assert ceilings["provider_calls"] == 0
    assert ceilings["human_reviews"] == 0
    assert ceilings["assessments_written"] == 0
    assert ceilings["labels_written"] == 0
    assert "packet selection" in excluded
    assert "human review" in excluded
    assert "assessment or label import" in excluded
