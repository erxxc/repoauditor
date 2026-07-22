"""SCA adapter — dependency vulnerability scanning via pip-audit and OSV-Scanner.

Runs both scanners over an ingested snapshot and normalizes their JSON into canonical
`CandidateFinding`s. Both are run because they have complementary coverage (pip-audit
reads the Python advisory DB against a resolved dependency set; OSV-Scanner reads
lockfiles across ecosystems against OSV).

An SCA finding is about a *dependency in a manifest*, not a code region, so it has no
meaningful line range. The canonical `Finding` requires integer `line_start`/`line_end`
(no nullable line convention exists — see store/models.py), so these anchor to line 1
of the manifest file, which is the honest "the whole manifest" location.

Degrades gracefully: a missing binary, a failed/timed-out run, or unparseable output
contributes no findings (logged), never raising.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path

from ...store.models import Severity
from ..ensemble import CandidateFinding
from ._common import relativize

logger = logging.getLogger(__name__)

TOOL_NAME = "sca"
_MANIFEST_GLOBS = ("requirements*.txt", "poetry.lock", "Pipfile.lock", "pdm.lock")
# SCA confirms a *known* CVE match against a declared dependency — the existence is
# reliable, but exploitability in this codebase is not, so a moderate confidence.
_SCA_CONFIDENCE = 0.6


class ScaAdapter:
    """Runs / parses pip-audit + OSV-Scanner and normalizes to candidate findings."""

    tool_name = TOOL_NAME

    def __init__(self, timeout_seconds: int = 180) -> None:
        self.timeout_seconds = timeout_seconds

    def run(self, snapshot_path: Path) -> list[CandidateFinding]:
        candidates: list[CandidateFinding] = []
        candidates += self._run_pip_audit(snapshot_path)
        candidates += self._run_osv_scanner(snapshot_path)
        return candidates

    # -- pip-audit ---------------------------------------------------------- #
    def _run_pip_audit(self, snapshot_path: Path) -> list[CandidateFinding]:
        if shutil.which("pip-audit") is None:
            logger.info("pip-audit not installed; skipping")
            return []
        reqs = sorted(snapshot_path.glob("requirements*.txt"))
        if not reqs:
            return []
        out: list[CandidateFinding] = []
        for req in reqs:
            try:
                proc = subprocess.run(
                    ["pip-audit", "-r", str(req), "-f", "json", "--progress-spinner", "off"],
                    capture_output=True, text=True, timeout=self.timeout_seconds,
                )
            except (subprocess.TimeoutExpired, OSError) as exc:
                logger.warning("pip-audit run failed (%s); skipping %s", exc, req.name)
                continue
            if proc.stdout.strip():
                out += self.parse_pip_audit(
                    proc.stdout, relativize(str(req), snapshot_path))
        return out

    def parse_pip_audit(self, raw_output: str,
                        manifest: str = "requirements.txt") -> list[CandidateFinding]:
        """Parse pip-audit `-f json` output (dependency list or {dependencies:[...]})."""
        try:
            doc = json.loads(raw_output)
        except json.JSONDecodeError as exc:
            logger.warning("could not parse pip-audit JSON (%s)", exc)
            return []
        deps = doc.get("dependencies", doc) if isinstance(doc, dict) else doc
        out: list[CandidateFinding] = []
        for dep in deps or []:
            name = dep.get("name", "?")
            version = dep.get("version", "?")
            for vuln in dep.get("vulns", []) or []:
                vid = vuln.get("id", "UNKNOWN")
                fix = ", ".join(vuln.get("fix_versions", []) or []) or "no fixed version"
                desc = (vuln.get("description") or "").strip()
                out.append(CandidateFinding(
                    title=f"Vulnerable dependency {name} ({vid})",
                    file=manifest, line_start=1, line_end=1,
                    citation_snippet=f"{name}=={version} — {vid}",
                    source_tool=self.tool_name, confidence=_SCA_CONFIDENCE,
                    severity=Severity.MEDIUM,
                    rationale=f"{desc} (fix: {fix})".strip(),
                ))
        return out

    # -- OSV-Scanner -------------------------------------------------------- #
    def _run_osv_scanner(self, snapshot_path: Path) -> list[CandidateFinding]:
        if shutil.which("osv-scanner") is None:
            logger.info("osv-scanner not installed; skipping")
            return []
        try:
            proc = subprocess.run(
                ["osv-scanner", "--format", "json", "-r", str(snapshot_path)],
                capture_output=True, text=True, timeout=self.timeout_seconds,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.warning("osv-scanner run failed (%s); skipping", exc)
            return []
        if not proc.stdout.strip():
            return []
        return self.parse_osv(proc.stdout, snapshot_path)

    def parse_osv(self, raw_output: str,
                  snapshot_path: Path | None = None) -> list[CandidateFinding]:
        """Parse `osv-scanner --format json` output into candidate findings."""
        try:
            doc = json.loads(raw_output)
        except json.JSONDecodeError as exc:
            logger.warning("could not parse osv-scanner JSON (%s)", exc)
            return []
        out: list[CandidateFinding] = []
        for result in doc.get("results", []) or []:
            manifest = relativize(
                (result.get("source", {}) or {}).get("path", "manifest"), snapshot_path)
            for pkg in result.get("packages", []) or []:
                info = pkg.get("package", {}) or {}
                name, version = info.get("name", "?"), info.get("version", "?")
                for vuln in pkg.get("vulnerabilities", []) or []:
                    vid = vuln.get("id", "UNKNOWN")
                    summary = (vuln.get("summary") or vuln.get("details") or "").strip()
                    out.append(CandidateFinding(
                        title=f"Vulnerable dependency {name} ({vid})",
                        file=manifest, line_start=1, line_end=1,
                        citation_snippet=f"{name}@{version} — {vid}",
                        source_tool=self.tool_name, confidence=_SCA_CONFIDENCE,
                        severity=Severity.MEDIUM, rationale=summary[:500],
                    ))
        return out

    def parse(self, raw_output: str) -> list[CandidateFinding]:
        """Parse pre-captured output, auto-detecting the producer (OSV vs pip-audit)."""
        try:
            doc = json.loads(raw_output)
        except json.JSONDecodeError:
            return []
        if isinstance(doc, dict) and "results" in doc:
            return self.parse_osv(raw_output)
        return self.parse_pip_audit(raw_output)
