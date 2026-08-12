"""Current documentation stays aligned while immutable evidence remains historical."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
LEDGER = DOCS / "optimizations/optimization-status.json"
CHECKPOINT = DOCS / "optimizations/outstanding-work-checkpoint-2026-08-07.json"


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_documentation_authority_matches_canonical_lifecycle():
    ledger = _json(LEDGER)
    checkpoint = _json(CHECKPOINT)
    authority = (DOCS / "documentation-status.md").read_text(encoding="utf-8")
    open_ids = [
        item["id"]
        for item in sorted(
            (item for item in ledger["items"] if item["status"] == "open"),
            key=lambda item: item["next_priority"],
        )
    ]

    assert ledger["summary"] == {"closed": 32, "open": 3, "total": 35}
    assert open_ids == ["OPT-009", "OPT-014", "OPT-010"]
    assert checkpoint["optimization_summary"] == ledger["summary"]
    assert {
        item["id"] for item in checkpoint["open_optimizations_in_priority_order"]
    } == set(open_ids)
    assert "32 closed, 3 open, 35 total" in authority
    assert "No paid" in authority and "provider execution is currently authorized" in authority


def test_current_documents_do_not_restore_superseded_blockers():
    current_paths = [
        DOCS / "documentation-status.md",
        DOCS / "prior-scope-roadmap.md",
        DOCS / "pre-tuning-readiness.md",
        DOCS / "quantitative-integrity-audit.md",
    ]
    current = "\n".join(path.read_text(encoding="utf-8") for path in current_paths)

    assert "six remaining gated optimizations" not in current
    assert "frequency-allocation defect is unresolved" not in current
    assert "repetition issue remains unresolved" not in current
    assert "OPT-005 same-store calibration is incomplete" not in current
    assert "36 labels" in current and "7 engagements" in current


def test_historical_documents_and_receipts_have_an_explicit_interpretation_rule():
    authority = (DOCS / "documentation-status.md").read_text(encoding="utf-8")
    readiness = (DOCS / "pre-tuning-readiness.md").read_text(encoding="utf-8")
    recovery = (DOCS / "poc-recovery-plan.md").read_text(encoding="utf-8")
    template = (DOCS / "poc-acceptance-walkthrough.md").read_text(encoding="utf-8")

    assert "Immutable execution evidence" in authority
    assert "Do not edit them to mimic" in authority
    assert "historical 2026-07-27 checkpoint" in readiness
    assert "Current reconciliation — 2026-08-07" in readiness
    assert "historical MVP execution record" in recovery
    assert "historical walkthrough template" in template
