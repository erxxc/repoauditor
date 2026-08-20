from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RECEIPT = ROOT / "docs/optimizations/opt-010-architecture-mechanism-eligibility-corrected-retry-receipt-2026-08-20.json"


def _payload() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_corrected_receipt_binds_the_exact_retained_stopped_attempt():
    retained = _payload()["retained_stopped_attempt"]
    for key in (
        "original_receipt", "stopped_result", "original_receipt_test",
    ):
        record = retained[key]
        assert _sha256(ROOT / record["path"]) == record["sha256"]
    assert retained["helper_before_correction"]["sha256"] == (
        "57146df0dd7570e22392943bd12a2a9db20f910892107e7bcb1b63dd8f691bd4"
    )
    assert retained["focused_test_before_correction"]["sha256"] == (
        "b01b10f21e326fce4fadf33b68d0454f41728a489ae6ba5c37774be1796ac9d4"
    )
    assert retained["provider_attempts"] == 0
    assert retained["source_transmissions"] == 0


def test_resume_requires_the_exact_matrix_only_artifact_state():
    retained = _payload()["retained_stopped_attempt"]
    assert retained["exact_artifact_inventory"] == [{
        "path": "mechanism-matrix.json",
        "sha256": "734d7bc40e54323b5bee963110c92f445b05f28c795e25f23884ede1d0e57ec3",
    }]
    assert "preserves the matrix byte-for-byte" in _payload()["permitted_correction"]["implementation_change"]


def test_keychain_loading_is_exact_ephemeral_and_has_no_fallback():
    correction = _payload()["permitted_correction"]
    assert "/usr/bin/security find-generic-password -w -s repoauditor-anthropic" in correction["credential_loading"]
    assert "Never print, log, persist, hash, count" in correction["credential_loading"]
    assert "stop without a provider retry or alternate credential source" in correction["no_fallback"]


def test_original_provider_and_source_ceilings_are_retained():
    ceilings = _payload()["cumulative_resource_ceilings"]
    assert ceilings["subjects"] == 6
    assert ceilings["provider_attempts"] == ceilings["authorized_public_source_transmissions"] == 12
    assert ceilings["provider_reported_tokens"] == 500000
    assert ceilings["maximum_known_dated_price_cost_usd"] == 7.5
    assert ceilings["allowed_network_hosts"] == ["api.anthropic.com"]


def test_corrected_retry_still_excludes_comparison_recall_and_closure():
    payload = _payload()
    statement = payload["authorization"]["required_statement"]
    assert payload["status"] == "authorization-pending"
    assert payload["authorization"]["granted"] is False
    assert "paired G03b comparison" in statement
    assert "G04 empirical recall evaluation" in statement
    assert "OPT-010 promotion or closure" in statement
    assert "cannot claim empirical safety" in payload["result_boundary"]
