"""Deployment-canary orchestration without launching external scanners."""

from __future__ import annotations

import json

from repoauditor.detect.deterministic import canaries
from repoauditor.detect.deterministic.execution import (
    SCANNER_TARGET_COUNT_BASES,
    ScannerExecution,
)


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
            "not-applicable"
            if status == "not-applicable"
            else SCANNER_TARGET_COUNT_BASES[scanner][0]
        ),
        applicability_detail=(
            "control contains no supported package source"
            if status == "not-applicable"
            else None
        ),
    )


def _result(scanner: str) -> canaries.ScannerCanaryResult:
    positive = canaries._positive_probe(_execution(scanner, "complete", 1, 1))
    clean = canaries._clean_probe(_execution(scanner, "empty", 0, 1))
    return canaries.ScannerCanaryResult(
        scanner=scanner,
        passed=True,
        provenance_passed=True,
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


def test_canary_provenance_is_scanner_specific():
    base = _execution("semgrep", "complete", 1, 1)
    semgrep = base.model_copy(update={
        "version": "1.170.1",
        "invocation": ("semgrep", "scan"),
        "configuration": "repoauditor-semgrep-canary-v1",
        "configuration_digest": "abc",
        "rule_count": 1,
        "configuration_resolution": "pinned-verified",
    })
    clean = semgrep.model_copy(update={
        "status": "empty",
        "finding_count": 0,
    })

    assert canaries._provenance_passed(
        "semgrep",
        canaries._positive_probe(semgrep),
        canaries._clean_probe(clean),
    )
    assert not canaries._provenance_passed(
        "semgrep",
        canaries._positive_probe(semgrep.model_copy(update={"rule_count": 0})),
        canaries._clean_probe(clean),
    )

    weak_rng = _execution("weak_rng", "complete", 1, 1).model_copy(update={
        "version": "weak_rng@v1",
        "invocation": ("weak_rng", "scan", "$SNAPSHOT"),
        "configuration": "weak_rng builtin idioms",
        "configuration_resolution": "embedded-default",
    })
    weak_rng_clean = weak_rng.model_copy(update={"status": "empty", "finding_count": 0})
    assert canaries._provenance_passed(
        "weak_rng",
        canaries._positive_probe(weak_rng),
        canaries._clean_probe(weak_rng_clean),
    )


def test_canary_orchestrator_never_persists_findings(monkeypatch):
    seen_roots = []

    def result(root, scanner):
        seen_roots.append(root)
        return _result(scanner)

    for name, scanner in (
        ("semgrep", "semgrep"),
        ("semgrep-supplemental", "semgrep-supplemental"),
        ("gitleaks", "gitleaks"),
        ("pip-audit", "pip-audit"),
        ("osv-scanner", "osv-scanner"),
        ("weak_rng", "weak_rng"),
    ):
        monkeypatch.setitem(
            canaries.CANARY_RUNNERS,
            name,
            lambda root, timeout, scanner=scanner: result(root, scanner),
        )

    report = canaries.run_scanner_canaries(timeout_seconds=1)
    rendered = json.loads(canaries.render_scanner_canaries(report))

    assert report.passed is True
    assert report.persisted_findings == 0
    assert rendered["schema_version"] == 2
    assert rendered["persisted_findings"] == 0
    assert all(item["provenance_passed"] for item in rendered["results"])
    assert {item["scanner"] for item in rendered["results"]} == {
        "semgrep", "semgrep-supplemental", "gitleaks", "pip-audit", "osv-scanner",
        "weak_rng",
    }
    assert seen_roots
    assert all(not root.exists() for root in seen_roots)


def test_canary_orchestrator_can_select_offline_subset(monkeypatch):
    called = []
    monkeypatch.setitem(
        canaries.CANARY_RUNNERS,
        "semgrep",
        lambda root, timeout: called.append("semgrep") or _result("semgrep"),
    )
    monkeypatch.setitem(
        canaries.CANARY_RUNNERS,
        "gitleaks",
        lambda root, timeout: called.append("gitleaks") or _result("gitleaks"),
    )

    report = canaries.run_scanner_canaries(1, ("semgrep", "gitleaks"))

    assert report.passed is True
    assert called == ["semgrep", "gitleaks"]
    assert [item.scanner for item in report.results] == ["semgrep", "gitleaks"]


def test_canary_orchestrator_rejects_unknown_empty_and_duplicate_selection():
    import pytest

    with pytest.raises(ValueError, match="unknown scanner"):
        canaries.run_scanner_canaries(1, ("unknown",))
    with pytest.raises(ValueError, match="at least one"):
        canaries.run_scanner_canaries(1, ())
    with pytest.raises(ValueError, match="unique"):
        canaries.run_scanner_canaries(1, ("gitleaks", "gitleaks"))
