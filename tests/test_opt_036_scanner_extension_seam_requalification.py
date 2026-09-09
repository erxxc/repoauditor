from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).parents[1]
RESULT = ROOT / "docs/optimizations/opt-036-scanner-extension-seam-requalification-corrected-retry-result-2026-09-09.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_opt036_result_binds_authority_implementation_and_lifecycle():
    result = json.loads(RESULT.read_text(encoding="utf-8"))

    assert result["status"] == "completed"
    assert _sha256(ROOT / result["receipt"]["path"]) == result["receipt"]["sha256"]
    assert (
        _sha256(ROOT / result["retained_stopped_result"]["path"])
        == result["retained_stopped_result"]["sha256"]
    )
    assert result["retained_stopped_result"]["retroactively_qualified"] is False
    for binding in result["implementation_bindings"].values():
        assert _sha256(ROOT / binding["path"]) == binding["sha256"]
    ledger = result["lifecycle"]["ledger"]
    assert _sha256(ROOT / ledger["path"]) == ledger["sha256"]
    assert result["lifecycle"]["summary"] == {"closed": 36, "open": 0, "total": 36}


def test_opt036_result_retains_zero_activity_and_claim_boundaries():
    result = json.loads(RESULT.read_text(encoding="utf-8"))

    assert all(value == 0 or value == 0.0 for value in result["activity"].values())
    assert result["validation"] == {
        "focused_passed": 68,
        "full_expression": "not live and not integration",
        "full_passed": 1235,
        "full_skipped": 2,
        "full_deselected": 36,
        "full_elapsed_seconds": 100.20,
        "external_scanner_processes": 0,
    }
    assert result["qualification"]["prng_lattice_lab_imports_executions_or_artifacts"] == 0
    assert "No recovery" in result["interpretation"]
