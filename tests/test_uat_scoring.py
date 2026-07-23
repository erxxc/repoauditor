"""Regression tests for methodology-safe live UAT scoring."""

from __future__ import annotations

from conftest import _load_fixture
from repoauditor.store.models import FalsificationStatus, Finding, Severity

from uat_scoring import score_live_uat


def _finding(**updates) -> Finding:
    values = {
        "repo_id": "uat",
        "title": "SQL injection",
        "file": "app.py",
        "line_start": 10,
        "line_end": 10,
        "citation_snippet": "unsafe_query(user_input)",
        "source_lens": "owasp",
        "confidence": 0.8,
        "severity": Severity.HIGH,
        "falsification_status": FalsificationStatus.CONFIRMED,
    }
    values.update(updates)
    return Finding(**values)


def _expected() -> dict:
    return {
        "findings": [
            {
                "case": 1, "title": "SQL injection", "file": "app.py",
                "line_start": 10, "line_end": 10, "severity": "critical",
                "citation_contains": "unsafe_query",
            },
            {
                "case": 5, "title": "Vulnerable dependency", "file": "requirements.txt",
                "line_start": 1, "line_end": 1, "severity": "medium",
                "citation_contains": "requests",
            },
        ],
        "expected_killed": [
            {"case": 7, "file": "guarded.py", "citation_contains": "owns_resource"},
        ],
        "expected_unresolved": [
            {"case": 9, "file": "ambiguous.py", "citation_contains": "return_target"},
        ],
        "planted_cases": [
            {
                "case": 1, "id": "sqli", "category": "sql-injection",
                "in_findings_ground_truth": True,
                "severity_range": ["high", "critical"],
                "expected_sources": [{"type": "lens", "name": "owasp"}],
                "expected_disposition": "confirmed",
                "location": {"line_approx": 10},
            },
            {
                "case": 5, "id": "dependency", "category": "dependency",
                "in_findings_ground_truth": True,
                "severity_range": ["medium"],
                "expected_sources": [{"type": "tool", "name": "sca"}],
                "expected_disposition": "confirmed",
                "location": {"line_approx": 1},
            },
            {
                "case": 7, "id": "guarded", "category": "mitigating-control",
                "in_findings_ground_truth": False,
                "severity_range": ["low"],
                "expected_sources": [{"type": "lens", "name": "owasp"}],
                "expected_disposition": "killed",
                "location": {"line_approx": 20},
            },
            {
                "case": 9, "id": "ambiguous", "category": "ambiguous",
                "in_findings_ground_truth": False,
                "severity_range": ["low", "medium"],
                "expected_sources": [{"type": "lens", "name": "owasp"}],
                "expected_disposition": "requires-review",
                "location": {"line_approx": 30},
            },
        ],
    }


def test_live_uat_collapses_cross_lens_duplicates_and_separates_severity():
    findings = [
        _finding(source_lens="owasp", confidence=0.9, severity=Severity.HIGH),
        _finding(source_lens="agentic_surface", confidence=0.7, severity=Severity.CRITICAL),
    ]

    result = score_live_uat(findings, _expected())
    final = result["final_countable_confirmed"]

    assert final["tp"] == 1
    assert final["fp"] == 0
    assert final["fn"] == 0
    assert final["precision"] == 1.0
    assert final["recall"] == 1.0
    assert final["severity_accuracy_on_matched"] == 1.0
    assert result["collapsed_confirmed_duplicate_count"] == 1
    assert [case["case"] for case in result["excluded_expected_cases"]] == [5]


def test_live_uat_does_not_count_unresolved_as_confirmed_false_positive():
    findings = [
        _finding(
            title="Possible redirect", file="ambiguous.py", line_start=30, line_end=30,
            citation_snippet="return_target", severity=Severity.LOW,
            falsification_status=FalsificationStatus.UNRESOLVED,
        ),
    ]

    result = score_live_uat(findings, _expected())
    final = result["final_countable_confirmed"]

    assert final["tp"] == 0
    assert final["fp"] == 0
    assert final["fn"] == 1
    assert result["raw_disposition_counts"] == {"unresolved": 1}
    assert result["unresolved_case_checks"][0]["correct_disposition"] is True


def test_live_uat_reports_killed_control_case_without_adding_it_to_recall():
    findings = [
        _finding(
            title="Guarded IDOR", file="guarded.py", line_start=20, line_end=20,
            citation_snippet='@owns_resource("invoice")', severity=Severity.LOW,
            falsification_status=FalsificationStatus.KILLED,
        ),
    ]

    result = score_live_uat(findings, _expected())

    assert result["killed_case_checks"][0]["candidate_raised"] is True
    assert result["killed_case_checks"][0]["correct_disposition"] is True
    assert result["killed_case_checks"][0]["negative_control_passed"] is True
    assert result["final_countable_confirmed"]["expected_case_count"] == 1


def test_live_uat_real_fixture_denominator_matches_adjudicated_model_scope():
    fixture = _load_fixture("uat_lightweight_app")
    expected = fixture.expected

    result = score_live_uat([], expected, available_source_types={"lens"})

    assert expected["schema_version"] == "uat-expectation-2"
    assert result["final_countable_confirmed"]["expected_case_count"] == 3
    assert [case["case"] for case in result["excluded_expected_cases"]] == [5]
    assert [case["case"] for case in result["killed_case_checks"]] == [4, 7, 8, 9, 10]
    assert result["unresolved_case_checks"] == []
    case7 = next(case for case in result["killed_case_checks"] if case["case"] == 7)
    case10 = next(case for case in result["killed_case_checks"] if case["case"] == 10)
    assert case7["negative_control_passed"] is True
    assert case7["correct_disposition"] is False
    assert case10["source_coverage_status"] == "partial"
    assert case10["unavailable_expected_sources"] == [
        {"type": "tool", "name": "secrets"}
    ]
    config_source = (fixture.snapshot_path / "storefront" / "config.py").read_text()
    assert "local-dev-session-key" not in config_source
    assert "secrets.token_hex(32)" in config_source
