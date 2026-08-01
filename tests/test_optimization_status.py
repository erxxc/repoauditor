"""OPT-035 keeps optimization lifecycle and prioritization machine-checkable."""

from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).parents[1]
LEDGER_PATH = ROOT / "docs" / "optimizations" / "optimization-status.json"
REGISTER_PATH = ROOT / "docs" / "optimizations" / "optimization-register.md"


def _ledger() -> dict:
    return json.loads(LEDGER_PATH.read_text(encoding="utf-8"))


def test_optimization_status_is_contiguous_unique_and_complete():
    ledger = _ledger()
    items = ledger["items"]
    ids = [item["id"] for item in items]

    assert ledger["schema_version"] == 1
    assert ids == [f"OPT-{number:03d}" for number in range(1, 36)]
    assert len(ids) == len(set(ids))
    assert set(ledger["status_definitions"]) == {"closed", "open"}
    assert {item["status"] for item in items} <= {"closed", "open"}


def test_optimization_status_summary_and_open_priority_are_consistent():
    ledger = _ledger()
    items = ledger["items"]
    closed = [item for item in items if item["status"] == "closed"]
    open_items = [item for item in items if item["status"] == "open"]

    assert ledger["summary"] == {
        "closed": len(closed), "open": len(open_items), "total": len(items)
    }
    assert all(item["gate"] == "none" and item["next_priority"] is None for item in closed)
    priorities = sorted(item["next_priority"] for item in open_items)
    assert priorities == list(range(1, len(open_items) + 1))
    assert all(item["gate"] != "none" for item in open_items)


def test_status_ledger_matches_authoritative_register_ids_and_states():
    ledger = _ledger()
    register = REGISTER_PATH.read_text(encoding="utf-8")
    registered_ids = set(re.findall(r"OPT-\d{3}", register))

    assert {item["id"] for item in ledger["items"]} <= registered_ids
    for item in ledger["items"]:
        match = re.search(
            rf"(?m)^\s+[A-Z]\. {re.escape(item['id'])} —", register
        )
        assert match is not None, item["id"]
        start = match.start()
        heading = register[start:register.index("owner:", start)]
        if item["status"] == "closed":
            assert "implemented" in heading or "completed" in heading
        else:
            assert "deferred" in heading or "gated" in heading
