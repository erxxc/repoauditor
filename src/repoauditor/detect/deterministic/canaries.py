"""Isolated deployment canaries for deterministic scanner adapters."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from .execution import ScannerExecution
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
    positive: CanaryProbe
    clean: CanaryProbe


class ScannerCanaryReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[1] = 1
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
    return ScannerCanaryResult(
        scanner="semgrep",
        passed=positive.passed and clean.passed,
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
    return ScannerCanaryResult(
        scanner="gitleaks",
        passed=positive.passed and clean.passed,
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
    return ScannerCanaryResult(
        scanner="pip-audit",
        passed=positive.passed and clean.passed,
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
    return ScannerCanaryResult(
        scanner="osv-scanner",
        passed=positive.passed and clean.passed,
        positive=positive,
        clean=clean,
    )


def run_scanner_canaries(timeout_seconds: int = 180) -> ScannerCanaryReport:
    """Run isolated controls without ingesting source or opening the finding store."""
    with tempfile.TemporaryDirectory(prefix="repoauditor-scanner-canaries-") as tmp:
        root = Path(tmp)
        results = [
            _semgrep_canary(root, timeout_seconds),
            _gitleaks_canary(root, timeout_seconds),
            _pip_audit_canary(root, timeout_seconds),
            _osv_canary(root, timeout_seconds),
        ]
    return ScannerCanaryReport(
        passed=all(result.passed for result in results),
        results=results,
    )


def render_scanner_canaries(report: ScannerCanaryReport) -> str:
    return json.dumps(report.model_dump(mode="json"), indent=2) + "\n"
