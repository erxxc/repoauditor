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

import hashlib
import json
import logging
import os
import re
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
from .execution import ScannerExecution
from .provenance import (
    SEMGREP_CONFIGURATION,
    SEMGREP_RULESET_SHA256,
    canonical_semgrep_rule_id,
    pinned_semgrep_configuration,
    tool_version,
)

logger = logging.getLogger(__name__)

TOOL_NAME = "sast"
_BINARY = "semgrep"


def _normalized_sarif(raw_output: str, snapshot_path: Path) -> str:
    """Canonicalize vendored rule ids and repository paths before retaining SARIF."""
    document = json.loads(raw_output)

    def normalize_locations(value) -> None:
        if isinstance(value, dict):
            artifact = value.get("artifactLocation")
            if isinstance(artifact, dict) and isinstance(artifact.get("uri"), str):
                artifact["uri"] = relativize(artifact["uri"], snapshot_path)
            for child in value.values():
                normalize_locations(child)
        elif isinstance(value, list):
            for child in value:
                normalize_locations(child)

    def normalize_rule_metadata(value, original: str, canonical: str) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if isinstance(child, str):
                    value[key] = child.replace(original, canonical)
                else:
                    normalize_rule_metadata(child, original, canonical)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                if isinstance(child, str):
                    value[index] = child.replace(original, canonical)
                else:
                    normalize_rule_metadata(child, original, canonical)

    def normalize_snapshot_references(value) -> None:
        snapshot_prefix = f"{snapshot_path.resolve()}{os.sep}"
        if isinstance(value, dict):
            for key, child in value.items():
                if isinstance(child, str):
                    value[key] = child.replace(snapshot_prefix, "")
                else:
                    normalize_snapshot_references(child)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                if isinstance(child, str):
                    value[index] = child.replace(snapshot_prefix, "")
                else:
                    normalize_snapshot_references(child)

    for run in document.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        rule_ids: dict[str, str] = {}
        for rule in driver.get("rules", []):
            if isinstance(rule.get("id"), str):
                original = rule["id"]
                canonical = canonical_semgrep_rule_id(original)
                help_uri = rule.get("helpUri")
                if (
                    canonical == original
                    and isinstance(help_uri, str)
                    and help_uri.startswith("https://semgrep.dev/r/")
                ):
                    documented = help_uri.removeprefix("https://semgrep.dev/r/")
                    if original.endswith(f".{documented}"):
                        canonical = documented
                rule_ids[original] = canonical
                normalize_rule_metadata(rule, original, canonical)
            if isinstance(rule.get("name"), str):
                rule["name"] = canonical_semgrep_rule_id(rule["name"])
        for result in run.get("results", []):
            if isinstance(result.get("ruleId"), str):
                result["ruleId"] = rule_ids.get(
                    result["ruleId"], canonical_semgrep_rule_id(result["ruleId"])
                )
            nested_rule = result.get("rule")
            if isinstance(nested_rule, dict) and isinstance(nested_rule.get("id"), str):
                nested_rule["id"] = rule_ids.get(
                    nested_rule["id"], canonical_semgrep_rule_id(nested_rule["id"])
                )
        normalize_locations(run)
        normalize_snapshot_references(run)
    return json.dumps(document)


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
        self,
        timeout_seconds: int = 180,
        sarif_output_path: Path | None = None,
        configuration: str = SEMGREP_CONFIGURATION,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.sarif_output_path = sarif_output_path
        self.configuration = configuration
        self.run_status: str | None = None
        self.failure_detail: str | None = None
        self.target_count = 0
        self.output_valid = False
        self.finding_count = 0
        self.version: str | None = None
        self.configuration_digest: str | None = None
        self.rule_count: int | None = None
        self.configuration_resolution: str | None = None
        self.invocation: tuple[str, ...] = ()
        self._resolved_configuration: str | None = None

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
            self.configuration_resolution = "unavailable"
            self.write_empty_artifact("unavailable")
            return []
        if self.version is None:
            self.version = tool_version(
                _BINARY, "--version", timeout_seconds=self.timeout_seconds
            )
        if (
            self.configuration == SEMGREP_CONFIGURATION
            and self._resolved_configuration is None
        ):
            try:
                with pinned_semgrep_configuration(self.timeout_seconds) as (
                    resolved,
                    rule_count,
                ):
                    self._resolved_configuration = str(resolved)
                    self.configuration_digest = SEMGREP_RULESET_SHA256
                    self.rule_count = rule_count
                    self.configuration_resolution = "pinned-verified"
                    return self.run(snapshot_path)
            except RuntimeError as exc:
                self.failure_detail = str(exc)[:500]
                self.configuration_resolution = "failed"
                self.write_empty_artifact("failed")
                return []
            finally:
                self._resolved_configuration = None
        resolved_configuration = self._resolved_configuration or self.configuration
        if self.configuration != SEMGREP_CONFIGURATION:
            configuration_path = Path(resolved_configuration)
            if configuration_path.is_file():
                payload = configuration_path.read_bytes()
                self.configuration_digest = hashlib.sha256(payload).hexdigest()
                self.rule_count = len(re.findall(rb"(?m)^\s*- id:", payload))
                self.configuration_resolution = "pinned-verified"
            else:
                self.configuration_resolution = "live-service"
        configuration_placeholder = (
            "$VERIFIED_CONFIG"
            if self.configuration_resolution == "pinned-verified"
            else "$CONFIG"
        )
        self.invocation = (
            "semgrep",
            "scan",
            "--sarif",
            "--quiet",
            "--no-git-ignore",
            "--project-root",
            "$SNAPSHOT",
            "--json-output",
            "$TARGET_REPORT",
            "--config",
            configuration_placeholder,
            "$SNAPSHOT",
        )
        target_report: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                suffix=".json", delete=False
            ) as handle:
                target_report = Path(handle.name)
            proc = subprocess.run([
                _BINARY,
                "scan",
                "--sarif",
                "--quiet",
                "--no-git-ignore",
                "--project-root",
                str(snapshot_path),
                "--json-output",
                str(target_report),
                "--config",
                resolved_configuration,
                str(snapshot_path),
            ], capture_output=True, text=True, timeout=self.timeout_seconds)
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.warning("semgrep run failed (%s); no SAST findings", exc)
            self.failure_detail = f"{type(exc).__name__}: {exc}"[:500]
            self.write_empty_artifact("failed")
            return []
        finally:
            target_payload = (
                target_report.read_text()
                if target_report is not None and target_report.is_file()
                else ""
            )
            if target_report is not None:
                target_report.unlink(missing_ok=True)
        if not proc.stdout.strip():
            status = "failed" if getattr(proc, "returncode", 0) else "empty"
            if status == "failed":
                self.failure_detail = (
                    proc.stderr.strip() or f"exit code {proc.returncode}"
                )[:500]
            self.write_empty_artifact(status)
            return []
        try:
            target_doc = json.loads(target_payload)
            scanned_paths = target_doc["paths"]["scanned"]
            self.version = target_doc.get("version") or self.version
        except (json.JSONDecodeError, KeyError, TypeError):
            self.failure_detail = "Semgrep target report is missing or malformed"
            self.write_empty_artifact("failed")
            return []
        if not scanned_paths:
            self.failure_detail = "Semgrep selected zero targets"
            self.write_empty_artifact("failed")
            return []
        self.target_count = len(scanned_paths)
        try:
            normalized_sarif = _normalized_sarif(proc.stdout, snapshot_path)
        except (json.JSONDecodeError, TypeError) as exc:
            self.failure_detail = f"malformed SARIF JSON: {type(exc).__name__}: {exc}"[:500]
            self.write_empty_artifact("failed")
            return []
        findings = self.parse(normalized_sarif, snapshot_path)
        # Preserve only valid SARIF.  The generated artifact lives outside the raw
        # snapshot and is therefore safe to replace on a repeated detect run.
        try:
            load_sarif(normalized_sarif)
        except Exception as exc:
            self.failure_detail = f"malformed SARIF: {type(exc).__name__}: {exc}"[:500]
            self.write_empty_artifact("failed")
            return findings
        self.output_valid = True
        self.finding_count = len(findings)
        self.run_status = "complete" if findings else "empty"
        self._write_artifact(normalized_sarif)
        return findings

    def execution(self) -> ScannerExecution:
        status = self.run_status or "failed"
        detail = self.failure_detail
        if status == "failed" and not detail:
            detail = "scanner execution did not produce a terminal status"
        return ScannerExecution(
            scanner="semgrep",
            status=status,
            applicable=None if status in {"unavailable", "disabled"} else True,
            output_valid=self.output_valid,
            finding_count=self.finding_count,
            target_count=self.target_count,
            target_count_basis=(
                status if status in {"unavailable", "disabled"}
                else "scanner-reported-files"
            ),
            version=self.version,
            configuration=self.configuration,
            invocation=self.invocation,
            configuration_digest=self.configuration_digest,
            rule_count=self.rule_count,
            configuration_resolution=self.configuration_resolution,
            failure_detail=detail,
        )

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
