from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-010-java-ruby-scanner-cell-coverage-receipt-2026-08-20.json"


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_receipt_binds_current_negative_evidence_and_scanner_instruments():
    payload = _payload()
    for record in payload["frozen_inputs"].values():
        if isinstance(record, dict):
            assert _sha256(ROOT / record["path"]) == record["sha256"]
    for record in payload["frozen_instruments"].values():
        assert _sha256(ROOT / record["path"]) == record["sha256"]


def test_fixtures_are_exactly_two_supported_cells_with_positive_clean_pairs():
    fixtures = _payload()["frozen_fixture_contract"]["fixtures"]
    assert [(item["cell"], item["expectation"]) for item in fixtures] == [
        ("Java:ssrf", "positive"),
        ("Java:ssrf", "clean"),
        ("Ruby:unsafe_deserialization", "positive"),
        ("Ruby:unsafe_deserialization", "clean"),
    ]
    assert all(item["source_lines"] for item in fixtures)
    assert _payload()["frozen_fixture_contract"]["freeze_before_scanner_process"] is True


def test_runtime_uses_only_the_known_installed_semgrep_interpreter():
    contract = _payload()["runtime_contract"]
    assert contract["semgrep_version"] == "1.170.0"
    assert contract["installed_import_interpreter"] == "/opt/homebrew/Cellar/semgrep/1.170.0/libexec/bin/python"
    requirements = " ".join(contract["requirements"])
    assert "Do not probe the project .venv" in requirements
    assert "SEMGREP_LOG_FILE" in requirements
    assert "SEMGREP_VERSION_CACHE_PATH" in requirements
    assert "Do not rerun general canaries" in requirements


def test_coverage_classification_routes_gap_vs_source_scarcity():
    contract = _payload()["coverage_contract"]
    assert set(contract["per_cell_classification"]) == {
        "qualified-detectable",
        "coverage-gap",
        "clean-control-failure",
        "scanner-or-provenance-failure",
    }
    assert "source-scarcity" in contract["routing"]["all_cells_qualified_detectable"]
    assert "supplemental-rule qualification" in contract["routing"]["any_coverage_gap"]
    assert "do not run supplemental Semgrep" in contract["supplemental_applicability"]


def test_resource_boundary_is_four_scans_and_zero_live_external_activity():
    ceilings = _payload()["resource_ceilings"]
    assert ceilings["logical_scanner_processes"] == 4
    assert ceilings["maximum_elapsed_minutes"] == 10
    assert ceilings["maximum_new_data_bytes"] == 2 * 1024**2
    for field, value in ceilings.items():
        if field not in {"logical_scanner_processes", "maximum_elapsed_minutes", "maximum_new_data_bytes"}:
            assert value in {0, 0.0}


def test_receipt_is_pending_and_cannot_change_rules_or_opt010_status():
    payload = _payload()
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    statement = payload["authorization"]["required_statement"]
    assert "new or edited scanner rules" in statement
    assert "OPT-010 promotion or closure" in statement
    assert "exactly four ordered offline" in statement
