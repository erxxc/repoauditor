from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).parents[1]
DOCS = ROOT / "docs/optimizations"


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_opt037_is_admitted_but_every_execution_tier_remains_gated():
    ledger = _json(DOCS / "optimization-status.json")
    receipt = _json(DOCS / "opt-037-admission-receipt-2026-09-09.json")
    item = next(item for item in ledger["items"] if item["id"] == "OPT-037")

    assert ledger["summary"] == {"closed": 38, "open": 0, "total": 38}
    assert item["status"] == "closed" and item["next_priority"] is None
    assert item["gate"] == "none"
    assert receipt["admission_contract"]["lab_artifacts_transferred"] == 0
    assert receipt["admission_contract"]["calibration_implementations"] == 0
    assert all(value == 0 or value == 0.0 for value in receipt["activity_ceilings"].values())

    result = _json(DOCS / "opt-037-admission-result-2026-09-09.json")
    assert result["status"] == "completed"
    assert result["lifecycle"]["summary"] == {"closed": 36, "open": 1, "total": 37}
    assert result["activity"] == receipt["activity_ceilings"]


def test_opt037_proposal_preserves_corrected_claim_boundaries():
    proposal = (DOCS / "opt-037-calibration-evidence.md").read_text(encoding="utf-8")

    assert "48/49 covered cells" in proposal
    assert "31/31 covered scored cells" in proposal
    assert "bounded evidence ingestion" in proposal
    assert "strictly precede" in proposal
    assert "predictive quantiles, not confidence intervals" in proposal
    assert "independent numerical oracle" in proposal
    assert "Missing calibration evidence is informational" in proposal


def test_opt036_result_keeps_its_historical_lifecycle_digest():
    result = _json(
        DOCS / "opt-036-scanner-extension-seam-requalification-corrected-retry-result-2026-09-09.json"
    )
    historical = result["lifecycle"]["ledger"]
    assert historical["sha256"] == "4992df97583da83ab82f3ea6042e8c435af5923ecef0cb0247c5a35b00be8f91"
    assert _sha256(ROOT / historical["path"]) != historical["sha256"]
