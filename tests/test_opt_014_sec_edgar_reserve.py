from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RESERVE = ROOT / (
    "docs/optimizations/opt-014-sec-edgar-reserve-2026-08-18.json"
)


def _payload() -> dict:
    return json.loads(RESERVE.read_text(encoding="utf-8"))


def test_reserve_binds_screen_result_and_exact_sec_identity() -> None:
    payload = _payload()
    source = payload["source_screen"]
    source_path = (RESERVE.parent / source["path"]).resolve()

    assert hashlib.sha256(source_path.read_bytes()).hexdigest() == source["sha256"]
    assert payload["status"] == "reserve-recorded-not-selected"
    assert payload["reserve_identity"]["stable_identity_sha256"] == (
        "b530088756ec92eff78405dd536eebe370f9e34cba8a9f2a480aadea8bd7fffc"
    )
    assert payload["reserve_identity"]["source_selected"] is False
    assert payload["reserve_identity"]["acquisition_authorized"] is False


def test_reserve_preserves_material_incident_claim_boundary() -> None:
    payload = _payload()

    assert len(payload["hard_limitations"]) == 6
    assert any("zero-incident" in item for item in payload["hard_limitations"])
    assert any("realized-loss" in item for item in payload["hard_limitations"])
    assert "structurally limited reserve" in payload["bounded_interpretation"]
    assert "does not" in payload["bounded_interpretation"]


def test_reserve_performed_no_data_or_lifecycle_activity() -> None:
    boundary = _payload()["current_boundary"]

    assert all(value == 0 for key, value in boundary.items() if key != "source_selected")
    assert boundary["source_selected"] is False
