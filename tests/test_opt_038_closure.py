from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs/optimizations"


def _json(name: str) -> dict:
    return json.loads((DOCS / name).read_text(encoding="utf-8"))


def test_opt038_closes_at_bounded_scope_with_no_open_priority() -> None:
    ledger = _json("optimization-status.json")
    item = next(item for item in ledger["items"] if item["id"] == "OPT-038")
    result = _json("opt-038-closure-result-2026-09-10.json")
    assert ledger["summary"] == {"closed": 38, "open": 0, "total": 38}
    assert item["status"] == "closed" and item["gate"] == "none"
    assert item["next_priority"] is None
    assert result["lifecycle"]["remaining_priority"] == []
    assert "substring-detector" in result["interpretation"]
    assert "no recovery" in result["interpretation"]


def test_closure_binds_qualified_evidence_without_lattice_activity() -> None:
    result = _json("opt-038-closure-result-2026-09-10.json")
    for binding in result["evidence_bindings"].values():
        path = ROOT / binding["path"]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == binding["sha256"]
    assert result["activity"]["lattice_lab_imports_or_executions"] == 0
    assert result["activity"]["production_store_reads"] == 0
    assert result["activity"]["automatic_upgrades"] == 0
