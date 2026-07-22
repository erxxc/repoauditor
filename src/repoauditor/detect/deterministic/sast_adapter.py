"""SAST adapter — Semgrep, normalized through the shared SARIF reader.

Runs Semgrep (`--sarif`) over an ingested snapshot and converts its SARIF output into
canonical `CandidateFinding`s. The SARIF parser and the severity / tool-confidence
mapping are reused from `triage.features` — the very reader the triage stage ingests
SARIF with — so a Semgrep result becomes a finding the same way on both paths, rather
than a second, drifting parser.

Degrades gracefully: if the `semgrep` binary is absent, or the run fails or times out,
the adapter contributes no findings (logged) and never raises — a partial toolchain
must never break a detect run.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from ...triage.features import (
    SarifFinding,
    load_sarif,
    sarif_severity,
    sarif_tool_confidence,
)
from ..ensemble import CandidateFinding
from ._common import relativize

logger = logging.getLogger(__name__)

TOOL_NAME = "sast"
_BINARY = "semgrep"


def _empty_sarif(status: str) -> str:
    return json.dumps({
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "semgrep",
                "rules": [],
                "properties": {"repoauditorCoverageStatus": status},
            }},
            "results": [],
        }],
    })


class SastAdapter:
    """Runs / parses Semgrep and normalizes its SARIF output to candidate findings."""

    tool_name = TOOL_NAME

    def __init__(
        self, timeout_seconds: int = 180, sarif_output_path: Path | None = None,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.sarif_output_path = sarif_output_path
        self.run_status: str | None = None

    def _write_artifact(self, raw_output: str) -> None:
        if self.sarif_output_path is None:
            return
        self.sarif_output_path.parent.mkdir(parents=True, exist_ok=True)
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=self.sarif_output_path.parent,
                prefix=".semgrep-", suffix=".tmp", delete=False,
            ) as handle:
                temporary = Path(handle.name)
                os.chmod(temporary, 0o600)
                handle.write(raw_output)
            os.replace(temporary, self.sarif_output_path)
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()

    def write_empty_artifact(self, status: str) -> None:
        """Persist an explicit zero-result SARIF with its coverage status."""
        self.run_status = status
        self._write_artifact(_empty_sarif(status))

    def run(self, snapshot_path: Path) -> list[CandidateFinding]:
        if shutil.which(_BINARY) is None:
            logger.info("semgrep not installed; SAST adapter contributes no findings")
            self.write_empty_artifact("unavailable")
            return []
        try:
            proc = subprocess.run(
                [_BINARY, "scan", "--sarif", "--quiet", "--config", "auto",
                 str(snapshot_path)],
                capture_output=True, text=True, timeout=self.timeout_seconds,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.warning("semgrep run failed (%s); no SAST findings", exc)
            self.write_empty_artifact("failed")
            return []
        if not proc.stdout.strip():
            status = "failed" if getattr(proc, "returncode", 0) else "empty"
            self.write_empty_artifact(status)
            return []
        findings = self.parse(proc.stdout, snapshot_path)
        # Preserve only valid SARIF.  The generated artifact lives outside the raw
        # snapshot and is therefore safe to replace on a repeated detect run.
        try:
            load_sarif(proc.stdout)
        except Exception:
            self.write_empty_artifact("malformed")
            return findings
        self.run_status = "complete" if findings else "empty"
        self._write_artifact(proc.stdout)
        return findings

    def parse(self, raw_output: str,
              snapshot_path: Path | None = None) -> list[CandidateFinding]:
        """Parse Semgrep SARIF into candidate findings (pure — no tool needed)."""
        try:
            sarif_findings = load_sarif(raw_output)
        except Exception as exc:  # malformed tool output must not crash detect
            logger.warning("could not parse SAST SARIF (%s); no SAST findings", exc)
            return []
        return [self._to_candidate(f, snapshot_path) for f in sarif_findings]

    def _to_candidate(self, f: SarifFinding,
                      snapshot_path: Path | None) -> CandidateFinding:
        cwe = f" [CWE-{f.cwe}]" if f.cwe else ""
        return CandidateFinding(
            title=f.rule_name or f.rule_id,
            file=relativize(f.file, snapshot_path),
            line_start=f.line_start,
            line_end=max(f.line_end, f.line_start),
            citation_snippet=(f.snippet or f.message[:200] or f.rule_id),
            source_tool=self.tool_name,
            producer="semgrep",
            confidence=sarif_tool_confidence(f),
            severity=sarif_severity(f),
            rationale=f"{f.message} (rule {f.rule_id}){cwe}",
        )
