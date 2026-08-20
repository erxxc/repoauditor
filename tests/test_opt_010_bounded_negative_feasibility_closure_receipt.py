from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-010-bounded-negative-feasibility-closure-receipt-2026-08-20.json"


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_closure_receipt_binds_all_evidence_and_current_state_files():
    payload = _payload()
    for record in payload["frozen_evidence"].values():
        assert _sha256(ROOT / record["path"]) == record["sha256"]
    lifecycle_inputs = {
        "optimization_status", "optimization_register", "documentation_status",
        "project_priorities", "triage_accuracy_roadmap", "agentic_escalation_gate",
    }
    for name, record in payload["frozen_current_state"].items():
        if isinstance(record, dict) and "path" in record:
            if name in lifecycle_inputs:
                assert len(record["sha256"]) == 64
            else:
                assert _sha256(ROOT / record["path"]) == record["sha256"]
    assert _sha256(ROOT / "data/repoauditor.db") == payload["frozen_current_state"]["production_store_sha256"]
    assert _sha256(ROOT / "config.toml") == payload["frozen_current_state"]["configuration_sha256"]
    assert _sha256(ROOT / "src/repoauditor/config.py") == payload["frozen_current_state"]["configuration_schema_sha256"]


def test_closure_is_bounded_negative_not_universal_or_production_ready():
    interpretation = _payload()["closure_interpretation"]
    assert interpretation["status"] == "closed-not-justified-and-not-feasible-at-evaluated-scope"
    claims = " ".join(interpretation["claims_not_made"])
    assert "universally impossible" in claims
    assert "production activation" in claims
    assert "new lifecycle identity" in interpretation["future_work_rule"]


def test_lifecycle_target_is_exactly_all_closed_with_no_priority():
    reconciliation = _payload()["lifecycle_reconciliation"]
    assert reconciliation["summary_after"] == {"closed": 35, "open": 0, "total": 35}
    assert reconciliation["opt010_after"] == {"status": "closed", "gate": "none", "next_priority": None}
    assert reconciliation["open_priority_after"] == []
    assert "byte-identical historical 32-closed/3-open evidence" in reconciliation["historical_checkpoint_rule"]


def test_exact_historical_reconciliation_allowlist_covers_observed_failures():
    payload = _payload()
    baseline = payload["historical_test_reconciliation"]["baseline"]
    assert baseline == {"passed": 241, "failed": 11, "skipped": 2}
    allowed = payload["historical_test_reconciliation"]["allowed_tests"]
    assert len(allowed) == 7
    assert all(path in payload["allowlist"] for path in allowed)
    assert "tests/test_opt_010_readiness_audit.py" in allowed


def test_receipt_is_pending_and_forbids_integration_and_live_activity():
    payload = _payload()
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    ceilings = payload["resource_ceilings"]
    assert ceilings["maximum_new_data_bytes"] == 2 * 1024**2
    for field, value in ceilings.items():
        if field not in {"maximum_elapsed_minutes", "maximum_new_data_bytes"}:
            assert value in {0, 0.0}
    statement = payload["authorization"]["required_statement"]
    assert "35 closed and zero open" in statement
    assert "full offline non-live suite" in statement
    assert "integration, remote push, deployment" in statement
