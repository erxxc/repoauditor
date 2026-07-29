"""Secrets adapter — gitleaks, with the secret value redacted before it is persisted.

Runs gitleaks over an ingested snapshot and normalizes its JSON into canonical
`CandidateFinding`s. The store must never hold the raw secret, so the matched value is
masked out of the `citation_snippet` — the finding records *that* a secret was found,
its rule, and its location, never the credential itself.

Degrades gracefully: a missing binary, a failed/timed-out run, or unparseable output
contributes no findings (logged), never raising. gitleaks exits non-zero when it finds
leaks, so a non-zero return code is expected and not treated as failure.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from ...store.models import Severity
from ..ensemble import CandidateFinding
from ._common import relativize
from .execution import ScannerExecution
from .provenance import tool_version

logger = logging.getLogger(__name__)

TOOL_NAME = "secrets"
_BINARY = "gitleaks"
# A matched secret is a reliable existence signal; committed credentials are high-sev.
_SECRETS_CONFIDENCE = 0.8


def _redact(match: str, secret: str) -> str:
    """Mask the secret out of its surrounding match so no credential is persisted."""
    match = (match or "").strip()
    secret = (secret or "").strip()
    if secret and secret in match:
        match = match.replace(secret, "****")
    elif secret:  # secret not literally in match -> drop the match, keep only structure
        match = "****"
    return match[:180]


class SecretsAdapter:
    """Runs / parses gitleaks and normalizes its output to candidate findings."""

    tool_name = TOOL_NAME

    def __init__(self, timeout_seconds: int = 180) -> None:
        self.timeout_seconds = timeout_seconds
        self.run_status = "not-run"
        self.failure_detail: str | None = None
        self.output_valid = False
        self.finding_count = 0
        self.target_count = 0
        self.version: str | None = None
        self.invocation: tuple[str, ...] = ()

    def run(self, snapshot_path: Path) -> list[CandidateFinding]:
        if shutil.which(_BINARY) is None:
            logger.info("gitleaks not installed; secrets adapter contributes no findings")
            self.run_status = "unavailable"
            return []
        self.version = tool_version(
            _BINARY, "version", timeout_seconds=self.timeout_seconds
        )
        self.target_count = 1
        self.invocation = (
            "gitleaks", "detect", "--source", "$SNAPSHOT", "--no-git",
            "--report-format", "json", "--report-path", "$REPORT",
            "--no-banner", "--exit-code", "0",
        )
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "gitleaks.json"
            try:
                proc = subprocess.run(
                    [_BINARY, "detect", "--source", str(snapshot_path), "--no-git",
                     "--report-format", "json", "--report-path", str(report),
                     "--no-banner", "--exit-code", "0"],
                    capture_output=True, text=True, timeout=self.timeout_seconds,
                )
            except (subprocess.TimeoutExpired, OSError) as exc:
                logger.warning("gitleaks run failed (%s); no secret findings", exc)
                self.run_status = "failed"
                self.failure_detail = f"{type(exc).__name__}: {exc}"[:500]
                return []
            if proc.returncode != 0:
                self.run_status = "failed"
                self.failure_detail = (
                    proc.stderr.strip() or f"exit code {proc.returncode}"
                )[:500]
                return []
            if not report.is_file():
                self.run_status = "failed"
                self.failure_detail = (
                    proc.stderr.strip() or "scanner did not write its JSON report"
                )[:500]
                return []
            raw_report = report.read_text()
            try:
                parsed_report = json.loads(raw_report)
            except json.JSONDecodeError:
                parsed_report = None
            if not isinstance(parsed_report, list):
                self.run_status = "failed"
                self.failure_detail = "scanner returned malformed or unsupported JSON"
                return []
            findings = self.parse(raw_report, snapshot_path)
            self.output_valid = True
            self.finding_count = len(findings)
            self.run_status = "complete" if findings else "empty"
            return findings

    def execution(self) -> ScannerExecution:
        status = self.run_status
        detail = self.failure_detail
        if status == "not-run":
            status = "failed"
            detail = detail or "scanner execution did not run"
        return ScannerExecution(
            scanner="gitleaks",
            status=status,
            applicable=None if status == "unavailable" else True,
            output_valid=self.output_valid,
            finding_count=self.finding_count,
            target_count=self.target_count,
            target_count_basis=(
                "unavailable" if status == "unavailable" else "submitted-root"
            ),
            version=self.version,
            configuration="gitleaks embedded default",
            invocation=self.invocation,
            configuration_resolution=(
                "unavailable" if status == "unavailable" else "embedded-default"
            ),
            failure_detail=detail,
        )

    def parse(self, raw_output: str,
              snapshot_path: Path | None = None) -> list[CandidateFinding]:
        """Parse gitleaks JSON into candidate findings, with secrets redacted."""
        try:
            leaks = json.loads(raw_output) or []
        except json.JSONDecodeError as exc:
            logger.warning("could not parse gitleaks JSON (%s); no secret findings", exc)
            return []
        out: list[CandidateFinding] = []
        for leak in leaks:
            rule = leak.get("RuleID", "secret")
            start = int(leak.get("StartLine", 1) or 1)
            end = max(int(leak.get("EndLine", start) or start), start)
            redacted = _redact(leak.get("Match", ""), leak.get("Secret", ""))
            desc = (leak.get("Description") or "").strip()
            out.append(CandidateFinding(
                title=f"Hardcoded secret ({rule})",
                file=relativize(leak.get("File", ""), snapshot_path),
                line_start=start, line_end=end,
                citation_snippet=f"[{rule}] {redacted} (secret value redacted)",
                source_tool=self.tool_name, confidence=_SECRETS_CONFIDENCE,
                producer="gitleaks",
                severity=Severity.HIGH,
                rationale=f"{desc} — credential committed in source (value withheld).".strip(),
            ))
        return out
