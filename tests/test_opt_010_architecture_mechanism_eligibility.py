from __future__ import annotations

from repoauditor.eval.opt010_architecture_eligibility import (
    MAX_REQUEST_BYTES,
    MECHANISM_MATRIX,
    canonical_bytes,
    complete_request_bytes,
    exact_resume_state,
    fixed_mechanisms,
)

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RETRY_RECEIPT = ROOT / "docs/optimizations/opt-010-architecture-mechanism-eligibility-corrected-retry-receipt-2026-08-20.json"
CORRECTED_RESULT = ROOT / "docs/optimizations/opt-010-architecture-mechanism-eligibility-corrected-retry-result-2026-08-20.json"


def test_fixed_matrix_is_exhaustive_and_keeps_unsupported_languages():
    assert MECHANISM_MATRIX == {
        "Python": ["sql_injection", "command_injection", "ssrf"],
        "TypeScript": ["command_injection", "ssrf"],
        "Java": ["ssrf"],
        "Ruby": ["unsafe_deserialization"],
        "Go": [],
        "Rust": [],
    }


def test_assignment_uses_complete_language_row_only():
    assert fixed_mechanisms("Python") == ("sql_injection", "command_injection", "ssrf")
    assert fixed_mechanisms("Go") == ()


def test_assignment_fails_closed_for_unknown_languages():
    try:
        fixed_mechanisms("Kotlin")
    except ValueError as exc:
        assert "outside the frozen mechanism matrix" in str(exc)
    else:
        raise AssertionError("unknown language did not fail closed")


def test_complete_request_bound_includes_prompt_evidence_and_schema():
    measured = complete_request_bytes("system", "evidence")
    assert measured > len("systemevidence".encode())
    assert measured < MAX_REQUEST_BYTES


def test_canonical_encoding_is_stable_and_compact():
    assert canonical_bytes({"b": 2, "a": 1}) == b'{"a":1,"b":2}'


def test_corrected_resume_distinguishes_historical_matrix_only_state_from_completed_state():
    receipt = json.loads(RETRY_RECEIPT.read_text(encoding="utf-8"))
    result = json.loads(CORRECTED_RESULT.read_text(encoding="utf-8"))

    assert exact_resume_state(receipt) is False
    assert result["status"] == "complete-architecture-mechanism-eligibility"
    assert len(result["subjects"]) == 6
    assert all(subject["terminal_state"] == "completed" for subject in result["subjects"])
