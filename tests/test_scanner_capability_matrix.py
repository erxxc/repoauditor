"""OPT-030 capability matrix stays aligned with production scanner contracts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import get_args

from repoauditor.detect.deterministic.execution import (
    DETERMINISTIC_SCANNERS,
    ScannerStatus,
)


ROOT = Path(__file__).parents[1]
MATRIX_PATH = ROOT / "docs" / "scanner-capability-matrix.json"
GUIDE_PATH = ROOT / "docs" / "scanner-capability-matrix.md"


def test_capability_matrix_covers_every_production_scanner_and_status():
    matrix = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))

    assert tuple(item["id"] for item in matrix["scanners"]) == DETERMINISTIC_SCANNERS
    assert set(matrix["status_semantics"]) == set(get_args(ScannerStatus))
    assert set(matrix["claim_boundary"]) == {
        "execution_health",
        "detection_capability",
        "candidate_policy",
    }


def test_each_capability_entry_is_complete_and_links_retained_evidence():
    matrix = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
    required = {
        "id",
        "category",
        "adapter",
        "producer",
        "mechanisms",
        "ecosystems",
        "applicability",
        "inputs",
        "target_count_basis",
        "configuration",
        "strengths",
        "blind_spots",
        "canary",
        "evidence",
    }
    for scanner in matrix["scanners"]:
        assert set(scanner) == required
        for evidence in scanner["evidence"]:
            relative = evidence.split("#", 1)[0]
            assert (MATRIX_PATH.parent / relative).is_file(), (
                scanner["id"], evidence
            )


def test_matrix_discloses_actual_pip_audit_boundary_and_claim_limits():
    matrix = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
    by_id = {item["id"]: item for item in matrix["scanners"]}
    pip_audit = by_id["pip-audit"]

    assert "root-level requirements*.txt" in pip_audit["applicability"]
    blind_spots = " ".join(pip_audit["blind_spots"])
    assert "poetry.lock" in blind_spots
    assert "Pipfile.lock" in blind_spots
    assert "exhaustive recall" in matrix["claim_boundary"]["detection_capability"]
    guide = GUIDE_PATH.read_text(encoding="utf-8")
    assert "Applicability correction disclosed by OPT-030" in guide
    assert "historical audit is retained unchanged" in guide
