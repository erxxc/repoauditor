"""Deployment-canary orchestration without launching external scanners."""

from __future__ import annotations

import json

from repoauditor.detect.deterministic import canaries
from repoauditor.detect.deterministic.execution import ScannerExecution


def _execution(
    scanner: str, status: str, findings: int, targets: int
) -> ScannerExecution:
    return ScannerExecution(
        scanner=scanner,
        status=status,
        applicable=False if status == "not-applicable" else True,
        output_valid=status in {"complete", "empty"},
        finding_count=findings,
        target_count=targets,
        target_count_basis=(
            "not-applicable" if status == "not-applicable" else "submitted-root"
        ),
    )


def _result(scanner: str) -> canaries.ScannerCanaryResult:
    positive = canaries._positive_probe(_execution(scanner, "complete", 1, 1))
    clean = canaries._clean_probe(_execution(scanner, "empty", 0, 1))
    return canaries.ScannerCanaryResult(
        scanner=scanner,
        passed=True,
        positive=positive,
        clean=clean,
    )


def test_canary_probes_require_positive_and_clean_evidence():
    assert canaries._positive_probe(
        _execution("semgrep", "complete", 1, 1)
    ).passed is True
    assert canaries._positive_probe(
        _execution("semgrep", "empty", 0, 1)
    ).passed is False
    assert canaries._clean_probe(
        _execution("gitleaks", "empty", 0, 1)
    ).passed is True
    assert canaries._clean_probe(
        _execution("osv-scanner", "not-applicable", 0, 0),
        allow_not_applicable=True,
    ).passed is True


def test_canary_orchestrator_never_persists_findings(monkeypatch):
    seen_roots = []

    def result(root, scanner):
        seen_roots.append(root)
        return _result(scanner)

    for name, scanner in (
        ("_semgrep_canary", "semgrep"),
        ("_gitleaks_canary", "gitleaks"),
        ("_pip_audit_canary", "pip-audit"),
        ("_osv_canary", "osv-scanner"),
    ):
        monkeypatch.setattr(
            canaries,
            name,
            lambda root, timeout, scanner=scanner: result(root, scanner),
        )

    report = canaries.run_scanner_canaries(timeout_seconds=1)
    rendered = json.loads(canaries.render_scanner_canaries(report))

    assert report.passed is True
    assert report.persisted_findings == 0
    assert rendered["persisted_findings"] == 0
    assert {item["scanner"] for item in rendered["results"]} == {
        "semgrep", "gitleaks", "pip-audit", "osv-scanner",
    }
    assert seen_roots
    assert all(not root.exists() for root in seen_roots)
