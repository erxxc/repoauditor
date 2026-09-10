from __future__ import annotations

import hashlib
import json
from pathlib import Path

from repoauditor.analyze.integrity import AuditLevel, calibration_evidence_disclosure


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs/optimizations"
STORE = ROOT / "data/repoauditor.db"
EXPECTED_STORE_SHA256 = "468c8de903f6c4c0ed23304e59db150a1d5d0b6cf350247fba3bc3d2699caf5a"


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_opt037_closes_only_at_bounded_available_evidence_scope() -> None:
    ledger = _json(DOCS / "optimization-status.json")
    item = next(item for item in ledger["items"] if item["id"] == "OPT-037")
    disclosure = calibration_evidence_disclosure()

    assert ledger["summary"] == {"closed": 38, "open": 0, "total": 38}
    assert item == {
        "id": "OPT-037",
        "title": "Calibration evidence",
        "status": "closed",
        "gate": "none",
        "next_priority": None,
    }
    assert "Tier 0 exact-oracle coverage is available" in disclosure
    assert "Tier 1 descriptive reliability is available" in disclosure
    assert "Tier 2 estimator-coverage evidence is unavailable" in disclosure
    assert "does not establish predictive validity" in disclosure
    assert AuditLevel.INFO.value == "info"


def test_tier_results_and_store_remain_bound_without_raw_disclosure() -> None:
    tier0 = _json(DOCS / "opt-037-tier-0-calibration-qualification-result-2026-09-10.json")
    tier1 = _json(DOCS / "opt-037-tier-1-reliability-result-2026-09-10.json")

    assert tier0["status"].startswith("completed")
    assert tier1["status"] == "completed-descriptive-reliability"
    assert tier1["cohort"]["eligible_identities"] == 104
    assert tier1["cohort"]["evaluation_families"] == 15
    assert tier1["disclosure"] == {
        "identities": 0,
        "individual_scores": 0,
        "individual_outcomes": 0,
        "sources": 0,
        "row_level_records": 0,
    }
    assert tier1["store"] == {
        "before_sha256": EXPECTED_STORE_SHA256,
        "after_sha256": EXPECTED_STORE_SHA256,
        "byte_identical": True,
        "mutations": 0,
    }
    if STORE.exists():
        assert _sha256(STORE) == EXPECTED_STORE_SHA256


def test_historical_admission_result_remains_historical() -> None:
    admission = _json(DOCS / "opt-037-admission-result-2026-09-09.json")
    receipt = _json(DOCS / "opt-037-admission-receipt-2026-09-09.json")
    assert admission["lifecycle"]["summary"] == {"closed": 36, "open": 1, "total": 37}
    assert admission["activity"]["provider_calls"] == 0
    assert admission["activity"]["calibration_runs"] == 0
    assert receipt["admission_contract"]["lab_artifacts_transferred"] == 0
