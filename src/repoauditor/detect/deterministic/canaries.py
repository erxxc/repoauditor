"""Isolated deployment canaries for deterministic scanner adapters."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from .execution import ScannerExecution
from .provenance import supplemental_semgrep_provenance
from .sast_adapter import SastAdapter
from .sca_adapter import ScaAdapter
from .secrets_adapter import SecretsAdapter


class CanaryProbe(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    expectation: Literal["positive", "clean", "not-applicable"]
    passed: bool
    execution: ScannerExecution


class ScannerCanaryResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scanner: str
    passed: bool
    provenance_passed: bool
    positive: CanaryProbe
    clean: CanaryProbe


class ScannerCanaryReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[2] = 2
    passed: bool
    results: list[ScannerCanaryResult]
    persisted_findings: Literal[0] = 0


def _write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _positive_probe(execution: ScannerExecution) -> CanaryProbe:
    return CanaryProbe(
        expectation="positive",
        passed=(
            execution.status in {"complete", "partial"}
            and execution.output_valid
            and execution.finding_count > 0
            and execution.target_count > 0
        ),
        execution=execution,
    )


def _clean_probe(
    execution: ScannerExecution, *, allow_not_applicable: bool = False
) -> CanaryProbe:
    expectation = "not-applicable" if allow_not_applicable else "clean"
    passed = (
        execution.status == "not-applicable"
        if allow_not_applicable
        else (
            execution.status == "empty"
            and execution.output_valid
            and execution.finding_count == 0
            and execution.target_count > 0
        )
    )
    return CanaryProbe(
        expectation=expectation,
        passed=passed,
        execution=execution,
    )


def _provenance_passed(
    scanner: str, positive: CanaryProbe, clean: CanaryProbe
) -> bool:
    executions = (positive.execution, clean.execution)
    if not all(item.version and item.invocation for item in executions):
        return False
    if scanner in {"semgrep", "semgrep-supplemental"}:
        return all(
            item.configuration_resolution == "pinned-verified"
            and item.configuration_digest
            and item.rule_count is not None
            and item.rule_count > 0
            for item in executions
        )
    if scanner == "gitleaks":
        return all(
            item.configuration_resolution == "embedded-default"
            and item.configuration == "gitleaks embedded default"
            for item in executions
        )
    if scanner == "pip-audit":
        return all(
            item.configuration_resolution == "live-service"
            and item.advisory_database == "PyPI Advisory Database"
            and item.advisory_database_checked_at is not None
            for item in executions
        )
    if scanner == "osv-scanner":
        return (
            positive.execution.configuration_resolution == "live-service"
            and positive.execution.advisory_database == "OSV.dev"
            and positive.execution.advisory_database_checked_at is not None
            and clean.execution.configuration_resolution == "not-applicable"
            and clean.execution.advisory_database == "OSV.dev"
        )
    return False


def _semgrep_canary(root: Path, timeout_seconds: int) -> ScannerCanaryResult:
    rules = root / "semgrep-canary.yml"
    rules.write_text(
        "rules:\n"
        "  - id: repoauditor-deployment-command-shell\n"
        "    languages: [python]\n"
        "    severity: ERROR\n"
        "    message: deployment canary\n"
        "    patterns:\n"
        "      - pattern: subprocess.run($CMD, shell=True, ...)\n"
    )
    positive_root = root / "semgrep-positive"
    clean_root = root / "semgrep-clean"
    _write(
        positive_root,
        "service.py",
        "import subprocess\nsubprocess.run(user_input, shell=True)\n",
    )
    _write(
        clean_root,
        "service.py",
        "import subprocess\nsubprocess.run([\"printf\", \"ok\"], check=True)\n",
    )
    positive_adapter = SastAdapter(timeout_seconds, configuration=str(rules))
    positive_adapter.run(positive_root)
    clean_adapter = SastAdapter(timeout_seconds, configuration=str(rules))
    clean_adapter.run(clean_root)
    positive = _positive_probe(positive_adapter.execution().model_copy(
        update={"configuration": "repoauditor-semgrep-canary-v1"}
    ))
    clean = _clean_probe(clean_adapter.execution().model_copy(
        update={"configuration": "repoauditor-semgrep-canary-v1"}
    ))
    provenance_passed = _provenance_passed("semgrep", positive, clean)
    return ScannerCanaryResult(
        scanner="semgrep",
        passed=positive.passed and clean.passed and provenance_passed,
        provenance_passed=provenance_passed,
        positive=positive,
        clean=clean,
    )


def _supplemental_semgrep_canary(
    root: Path, timeout_seconds: int
) -> ScannerCanaryResult:
    rules, digest, _ = supplemental_semgrep_provenance()
    positive_root = root / "semgrep-supplemental-positive"
    clean_root = root / "semgrep-supplemental-clean"
    _write(
        positive_root,
        "service.js",
        (
            "const { execSync } = require('child_process')\n"
            "function run(command) { return execSync(command) }\n"
        ),
    )
    _write(
        clean_root,
        "service.js",
        (
            "const { execFileSync } = require('child_process')\n"
            "execFileSync('node', ['--version'], { shell: false })\n"
        ),
    )
    options = {
        "configuration": str(rules),
        "configuration_label": f"repoauditor-supplemental@sha256:{digest}",
        "scanner_name": "semgrep-supplemental",
        "producer": "semgrep-supplemental",
        "applicable_extensions": frozenset({
            ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
        }),
    }
    positive_adapter = SastAdapter(timeout_seconds, **options)
    positive_adapter.run(positive_root)
    clean_adapter = SastAdapter(timeout_seconds, **options)
    clean_adapter.run(clean_root)
    positive = _positive_probe(positive_adapter.execution())
    clean = _clean_probe(clean_adapter.execution())
    provenance_passed = _provenance_passed(
        "semgrep-supplemental", positive, clean
    )
    return ScannerCanaryResult(
        scanner="semgrep-supplemental",
        passed=positive.passed and clean.passed and provenance_passed,
        provenance_passed=provenance_passed,
        positive=positive,
        clean=clean,
    )


def _gitleaks_canary(root: Path, timeout_seconds: int) -> ScannerCanaryResult:
    positive_root = root / "gitleaks-positive"
    clean_root = root / "gitleaks-clean"
    _write(
        positive_root,
        "settings.py",
        'API_TOKEN = "sk_live_51H8xExampleHardcodedSecretDoNotUse0000"\n',
    )
    _write(clean_root, "settings.py", 'API_TOKEN = "from-environment"\n')
    positive_adapter = SecretsAdapter(timeout_seconds)
    positive_adapter.run(positive_root)
    clean_adapter = SecretsAdapter(timeout_seconds)
    clean_adapter.run(clean_root)
    positive = _positive_probe(positive_adapter.execution())
    clean = _clean_probe(clean_adapter.execution())
    provenance_passed = _provenance_passed("gitleaks", positive, clean)
    return ScannerCanaryResult(
        scanner="gitleaks",
        passed=positive.passed and clean.passed and provenance_passed,
        provenance_passed=provenance_passed,
        positive=positive,
        clean=clean,
    )


def _pip_audit_canary(root: Path, timeout_seconds: int) -> ScannerCanaryResult:
    positive_root = root / "pip-audit-positive"
    clean_root = root / "pip-audit-clean"
    _write(positive_root, "requirements.txt", "requests==2.19.1\n")
    _write(clean_root, "requirements.txt", "# deliberately empty clean control\n")
    positive_adapter = ScaAdapter(timeout_seconds)
    positive_adapter._run_pip_audit(positive_root)
    clean_adapter = ScaAdapter(timeout_seconds)
    clean_adapter._run_pip_audit(clean_root)
    positive_execution = {
        item.scanner: item for item in positive_adapter.executions()
    }["pip-audit"]
    clean_execution = {
        item.scanner: item for item in clean_adapter.executions()
    }["pip-audit"]
    positive = _positive_probe(positive_execution)
    clean = _clean_probe(clean_execution)
    provenance_passed = _provenance_passed("pip-audit", positive, clean)
    return ScannerCanaryResult(
        scanner="pip-audit",
        passed=positive.passed and clean.passed and provenance_passed,
        provenance_passed=provenance_passed,
        positive=positive,
        clean=clean,
    )


def _osv_canary(root: Path, timeout_seconds: int) -> ScannerCanaryResult:
    positive_root = root / "osv-positive"
    clean_root = root / "osv-not-applicable"
    _write(positive_root, "requirements.txt", "requests==2.19.1\n")
    _write(clean_root, "README.md", "No package manifest in this control.\n")
    positive_adapter = ScaAdapter(timeout_seconds)
    positive_adapter._run_osv_scanner(positive_root)
    clean_adapter = ScaAdapter(timeout_seconds)
    clean_adapter._run_osv_scanner(clean_root)
    positive_execution = {
        item.scanner: item for item in positive_adapter.executions()
    }["osv-scanner"]
    clean_execution = {
        item.scanner: item for item in clean_adapter.executions()
    }["osv-scanner"]
    positive = _positive_probe(positive_execution)
    clean = _clean_probe(clean_execution, allow_not_applicable=True)
    provenance_passed = _provenance_passed("osv-scanner", positive, clean)
    return ScannerCanaryResult(
        scanner="osv-scanner",
        passed=positive.passed and clean.passed and provenance_passed,
        provenance_passed=provenance_passed,
        positive=positive,
        clean=clean,
    )


CANARY_RUNNERS = {
    "semgrep": _semgrep_canary,
    "semgrep-supplemental": _supplemental_semgrep_canary,
    "gitleaks": _gitleaks_canary,
    "pip-audit": _pip_audit_canary,
    "osv-scanner": _osv_canary,
}


def run_scanner_canaries(
    timeout_seconds: int = 180,
    scanners: tuple[str, ...] | None = None,
) -> ScannerCanaryReport:
    """Run isolated controls without ingesting source or opening the finding store."""
    selected = tuple(CANARY_RUNNERS) if scanners is None else scanners
    unknown = sorted(set(selected) - CANARY_RUNNERS.keys())
    if unknown:
        raise ValueError(f"unknown scanner canaries: {', '.join(unknown)}")
    if not selected:
        raise ValueError("at least one scanner canary is required")
    if len(selected) != len(set(selected)):
        raise ValueError("scanner canaries must be unique")
    with tempfile.TemporaryDirectory(prefix="repoauditor-scanner-canaries-") as tmp:
        root = Path(tmp)
        results = [CANARY_RUNNERS[name](root, timeout_seconds) for name in selected]
    return ScannerCanaryReport(
        passed=all(result.passed for result in results),
        results=results,
    )


def render_scanner_canaries(report: ScannerCanaryReport) -> str:
    return json.dumps(report.model_dump(mode="json"), indent=2) + "\n"
