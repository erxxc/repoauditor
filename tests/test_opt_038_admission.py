from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs/optimizations"


def _json(name: str) -> dict:
    return json.loads((DOCS / name).read_text(encoding="utf-8"))


def test_opt038_admission_is_historical_while_current_item_is_closed() -> None:
    ledger = _json("optimization-status.json")
    item = next(item for item in ledger["items"] if item["id"] == "OPT-038")
    assert ledger["summary"] == {"closed": 38, "open": 0, "total": 38}
    assert item == {
        "id": "OPT-038",
        "title": "Python weak-RNG syntactic detector",
        "status": "closed",
        "gate": "none",
        "next_priority": None,
    }
    admission = _json("opt-038-admission-result-2026-09-10.json")
    assert admission["lifecycle"]["summary"] == {"closed": 37, "open": 1, "total": 38}


def test_donor_qualification_is_bounded_and_reproducible() -> None:
    result = _json("opt-038-donor-code-qualification-result-2026-09-10.json")
    assert result["donor"]["commit"] == "10057b6574cbd4ce5663af9399ef69a46b9ec7f4"
    assert result["donor"]["three_way_conflicts"] == 0
    assert len(result["eight_file_inventory"]) == 8
    assert result["qualification"]["focused_tests_passed"] == 22
    assert result["qualification"]["lattice_lab_import_execution_or_artifact_ingestion"] is False
    assert result["qualification"]["automatic_actionability_upgrade"] is False
    limitations = " ".join(result["bounded_limitations"])
    assert "aliased" in limitations and "shadowed" in limitations
    assert "target count" in limitations and "private" in limitations


def test_implementation_receipt_precedes_code_import() -> None:
    receipt = _json("opt-038-implementation-receipt-2026-09-10.json")
    admission = _json("opt-038-admission-result-2026-09-10.json")
    assert receipt["authorization_state"].startswith("receipt frozen")
    assert "src/repoauditor/detect/deterministic/plugins/weak_rng_py.py" in receipt["allowed_files"]
    assert admission["implementation"]["code_imported"] is False
    assert admission["implementation"]["execution_authorized"] is False
    assert all(value == 0 for value in admission["activity"].values())
