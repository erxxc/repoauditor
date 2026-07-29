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
import re
import shutil
import subprocess
from pathlib import Path

from ...store.models import Severity
from ..ensemble import CandidateFinding
from ._common import relativize
from .execution import ScannerExecution
from .provenance import tool_version, utc_now

logger = logging.getLogger(__name__)

TOOL_NAME = "sca"
_MANIFEST_GLOBS = ("requirements*.txt", "poetry.lock", "Pipfile.lock", "pdm.lock")
_MAX_EXPLICIT_OSV_REQUIREMENTS = 100
# SCA confirms a *known* CVE match against a declared dependency — the existence is
# reliable, but exploitability in this codebase is not, so a moderate confidence.
_SCA_CONFIDENCE = 0.6
_EXACT_REQUIREMENT = re.compile(
    r"^[A-Za-z0-9_.-]+(?:\[[^\]]+\])?==[^;\s]+(?:\s*;.*)?$"
)


def _valid_pip_audit_json(raw_output: str) -> bool:
    try:
        doc = json.loads(raw_output)
    except json.JSONDecodeError:
        return False
    dependencies = doc.get("dependencies") if isinstance(doc, dict) else doc
    return isinstance(dependencies, list)


def _valid_osv_json(raw_output: str) -> bool:
    try:
        doc = json.loads(raw_output)
    except json.JSONDecodeError:
        return False
    return isinstance(doc, dict) and isinstance(doc.get("results"), list)


def _identity(ecosystem: str, package: str, version: str, advisory_id: str) -> str:
    """Canonical natural key for one affected dependency/advisory tuple."""
    parts = (ecosystem, package, version, advisory_id)
    return "sca:" + ":".join(str(part).strip().lower() for part in parts)


def _direct_pins_only(path: Path) -> bool:
    """Whether pip-audit can safely use its no-pip, direct-dependency fallback."""
    requirements = [
        line.strip()
        for line in path.read_text(errors="replace").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    return bool(requirements) and all(_EXACT_REQUIREMENT.match(line) for line in requirements)


class ScaAdapter:
    """Runs / parses pip-audit + OSV-Scanner and normalizes to candidate findings."""

    tool_name = TOOL_NAME

    def __init__(self, timeout_seconds: int = 180) -> None:
        self.timeout_seconds = timeout_seconds
        self.run_statuses = {"pip-audit": "not-run", "osv-scanner": "not-run"}
        self.failure_details: dict[str, str] = {}
        self.target_counts = {"pip-audit": 0, "osv-scanner": 0}
        self.output_valid = {"pip-audit": False, "osv-scanner": False}
        self.finding_counts = {"pip-audit": 0, "osv-scanner": 0}
        self.versions = {"pip-audit": None, "osv-scanner": None}
        self.invocations: dict[str, tuple[str, ...]] = {
            "pip-audit": (),
            "osv-scanner": (),
        }
        self.database_checked_at = {"pip-audit": None, "osv-scanner": None}

    def run(self, snapshot_path: Path) -> list[CandidateFinding]:
        candidates: list[CandidateFinding] = []
        candidates += self._run_pip_audit(snapshot_path)
        candidates += self._run_osv_scanner(snapshot_path)
        return candidates

    # -- pip-audit ---------------------------------------------------------- #
    def _run_pip_audit(self, snapshot_path: Path) -> list[CandidateFinding]:
        if shutil.which("pip-audit") is None:
            logger.info("pip-audit not installed; skipping")
            self.run_statuses["pip-audit"] = "unavailable"
            return []
        self.versions["pip-audit"] = tool_version(
            "pip-audit", "--version", timeout_seconds=self.timeout_seconds
        )
        reqs = sorted(snapshot_path.glob("requirements*.txt"))
        if not reqs:
            self.run_statuses["pip-audit"] = "not-applicable"
            return []
        self.target_counts["pip-audit"] = len(reqs)
        out: list[CandidateFinding] = []
        for req in reqs:
            self.invocations["pip-audit"] = (
                "pip-audit", "-r", "$MANIFEST", "-f", "json",
                "--progress-spinner", "off",
            )
            self.database_checked_at["pip-audit"] = utc_now()
            try:
                proc = subprocess.run(
                    ["pip-audit", "-r", str(req), "-f", "json", "--progress-spinner", "off"],
                    capture_output=True, text=True, timeout=self.timeout_seconds,
                )
            except (subprocess.TimeoutExpired, OSError) as exc:
                logger.warning("pip-audit run failed (%s); skipping %s", exc, req.name)
                self.run_statuses["pip-audit"] = "failed"
                self.failure_details["pip-audit"] = f"{type(exc).__name__}: {exc}"[:500]
                continue
            if proc.returncode not in {0, 1}:
                primary_failure = (
                    proc.stderr.strip() or f"exit code {proc.returncode}"
                )[:350]
                if _direct_pins_only(req):
                    self.invocations["pip-audit"] = (
                        "pip-audit", "-r", "$MANIFEST", "-f", "json",
                        "--progress-spinner", "off", "--disable-pip", "--no-deps",
                    )
                    try:
                        proc = subprocess.run(
                            [
                                "pip-audit", "-r", str(req), "-f", "json",
                                "--progress-spinner", "off", "--disable-pip", "--no-deps",
                            ],
                            capture_output=True, text=True, timeout=self.timeout_seconds,
                        )
                    except (subprocess.TimeoutExpired, OSError) as exc:
                        proc = None
                        fallback_failure = f"{type(exc).__name__}: {exc}"
                    else:
                        fallback_failure = (
                            proc.stderr.strip() or f"exit code {proc.returncode}"
                        )
                    if (
                        proc is not None
                        and proc.returncode in {0, 1}
                        and proc.stdout.strip()
                        and _valid_pip_audit_json(proc.stdout)
                    ):
                        out += self.parse_pip_audit(
                            proc.stdout, relativize(str(req), snapshot_path)
                        )
                        self.run_statuses["pip-audit"] = "partial"
                        self.output_valid["pip-audit"] = True
                        self.failure_details["pip-audit"] = (
                            "full dependency resolution failed; audited exact direct pins "
                            f"without transitive resolution. Primary detail: {primary_failure}"
                        )[:500]
                        continue
                    primary_failure += f"; direct-pin fallback failed: {fallback_failure[:120]}"
                self.run_statuses["pip-audit"] = "failed"
                self.failure_details["pip-audit"] = primary_failure[:500]
                continue
            if proc.stdout.strip():
                if not _valid_pip_audit_json(proc.stdout):
                    self.run_statuses["pip-audit"] = "failed"
                    self.failure_details["pip-audit"] = (
                        "scanner returned malformed or unsupported JSON"
                    )
                    continue
                out += self.parse_pip_audit(
                    proc.stdout, relativize(str(req), snapshot_path))
            else:
                self.run_statuses["pip-audit"] = "failed"
                self.failure_details["pip-audit"] = "scanner returned no JSON output"
        if self.run_statuses["pip-audit"] not in {"failed", "partial"}:
            self.run_statuses["pip-audit"] = "complete" if out else "empty"
            self.output_valid["pip-audit"] = True
        self.finding_counts["pip-audit"] = len(out)
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
                    identity_key=_identity("pypi", name, version, vid),
                    source_tool=self.tool_name, confidence=_SCA_CONFIDENCE,
                    producer="pip-audit",
                    severity=Severity.MEDIUM,
                    rationale=f"{desc} (fix: {fix})".strip(),
                ))
        return out

    # -- OSV-Scanner -------------------------------------------------------- #
    def _run_osv_scanner(self, snapshot_path: Path) -> list[CandidateFinding]:
        if shutil.which("osv-scanner") is None:
            logger.info("osv-scanner not installed; skipping")
            self.run_statuses["osv-scanner"] = "unavailable"
            return []
        self.versions["osv-scanner"] = tool_version(
            "osv-scanner", "--version", timeout_seconds=self.timeout_seconds
        )
        self.target_counts["osv-scanner"] = 1
        self.invocations["osv-scanner"] = (
            "osv-scanner", "scan", "source", "--format", "json",
            "--recursive", "--no-ignore", "$SNAPSHOT",
        )
        self.database_checked_at["osv-scanner"] = utc_now()
        try:
            proc = subprocess.run(
                [
                    "osv-scanner",
                    "scan",
                    "source",
                    "--format",
                    "json",
                    "--recursive",
                    "--no-ignore",
                    str(snapshot_path),
                ],
                capture_output=True, text=True, timeout=self.timeout_seconds,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.warning("osv-scanner run failed (%s); skipping", exc)
            self.run_statuses["osv-scanner"] = "failed"
            self.failure_details["osv-scanner"] = f"{type(exc).__name__}: {exc}"[:500]
            return []
        if proc.returncode not in {0, 1}:
            primary_detail = proc.stderr.strip() or f"exit code {proc.returncode}"
            primary_failure = primary_detail[:350]
            if "no package sources found" in primary_detail.lower():
                discovered = sorted({
                    path
                    for path in snapshot_path.rglob("requirements*.txt")
                    if path.is_file()
                })
                explicit = discovered[:_MAX_EXPLICIT_OSV_REQUIREMENTS]
                if explicit:
                    findings: list[CandidateFinding] = []
                    fallback_failures: list[str] = []
                    only_no_source_failures = True
                    for requirement in explicit:
                        self.invocations["osv-scanner"] = (
                            "osv-scanner", "scan", "source", "--format", "json",
                            "--lockfile", "$MANIFEST",
                        )
                        try:
                            fallback = subprocess.run(
                                [
                                    "osv-scanner", "scan", "source", "--format", "json",
                                    "--lockfile", str(requirement),
                                ],
                                capture_output=True,
                                text=True,
                                timeout=self.timeout_seconds,
                            )
                        except (subprocess.TimeoutExpired, OSError) as exc:
                            only_no_source_failures = False
                            fallback_failures.append(
                                f"{requirement.name}: {type(exc).__name__}: {exc}"
                            )
                            continue
                        if fallback.returncode not in {0, 1}:
                            detail = fallback.stderr.strip() or (
                                f"exit code {fallback.returncode}"
                            )
                            if "no package sources found" not in detail.lower():
                                only_no_source_failures = False
                            fallback_failures.append(
                                f"{requirement.name}: {detail[:120]}"
                            )
                            continue
                        if not fallback.stdout.strip():
                            only_no_source_failures = False
                            fallback_failures.append(
                                f"{requirement.name}: scanner returned no JSON output"
                            )
                            continue
                        if not _valid_osv_json(fallback.stdout):
                            only_no_source_failures = False
                            fallback_failures.append(
                                f"{requirement.name}: malformed or unsupported JSON"
                            )
                            continue
                        findings += self.parse_osv(
                            fallback.stdout, snapshot_path
                        )
                    if not fallback_failures:
                        bounded = (
                            f" (bounded to {_MAX_EXPLICIT_OSV_REQUIREMENTS} of "
                            f"{len(discovered)})"
                            if len(discovered) > len(explicit)
                            else ""
                        )
                        self.run_statuses["osv-scanner"] = "partial"
                        self.target_counts["osv-scanner"] = len(explicit)
                        self.output_valid["osv-scanner"] = True
                        self.finding_counts["osv-scanner"] = len(findings)
                        self.failure_details["osv-scanner"] = (
                            "recursive manifest discovery failed; explicitly scanned "
                            f"{len(explicit)} requirements file(s){bounded}. Other manifest types "
                            f"may be uncovered. Primary detail: {primary_failure}"
                        )[:500]
                        return findings
                    if fallback_failures and only_no_source_failures:
                        self.run_statuses["osv-scanner"] = "not-applicable"
                        self.target_counts["osv-scanner"] = 0
                        self.database_checked_at["osv-scanner"] = None
                        return []
                    primary_failure += (
                        "; explicit requirements fallback failures: "
                        + "; ".join(fallback_failures)
                    )[:150]
                else:
                    self.run_statuses["osv-scanner"] = "not-applicable"
                    self.target_counts["osv-scanner"] = 0
                    self.database_checked_at["osv-scanner"] = None
                    return []
            self.run_statuses["osv-scanner"] = "failed"
            self.failure_details["osv-scanner"] = primary_failure[:500]
            return []
        if not proc.stdout.strip():
            self.run_statuses["osv-scanner"] = "failed"
            self.failure_details["osv-scanner"] = "scanner returned no JSON output"
            return []
        if not _valid_osv_json(proc.stdout):
            self.run_statuses["osv-scanner"] = "failed"
            self.failure_details["osv-scanner"] = (
                "scanner returned malformed or unsupported JSON"
            )
            return []
        findings = self.parse_osv(proc.stdout, snapshot_path)
        self.output_valid["osv-scanner"] = True
        self.finding_counts["osv-scanner"] = len(findings)
        self.run_statuses["osv-scanner"] = "complete" if findings else "empty"
        return findings

    def executions(self) -> list[ScannerExecution]:
        records = []
        for scanner in ("pip-audit", "osv-scanner"):
            status = self.run_statuses[scanner]
            detail = self.failure_details.get(scanner)
            if status == "not-run":
                status = "failed"
                detail = detail or "scanner execution did not run"
            if status in {"not-applicable", "unavailable"}:
                basis = status
                applicable = False if status == "not-applicable" else None
            else:
                basis = (
                    "submitted-manifests"
                    if scanner == "pip-audit"
                    else "submitted-root"
                )
                applicable = True
            records.append(ScannerExecution(
                scanner=scanner,
                status=status,
                applicable=applicable,
                output_valid=self.output_valid[scanner],
                finding_count=self.finding_counts[scanner],
                target_count=self.target_counts[scanner],
                target_count_basis=basis,
                version=self.versions[scanner],
                configuration=(
                    "PyPI vulnerability service"
                    if scanner == "pip-audit"
                    else "OSV.dev live API"
                ),
                invocation=self.invocations[scanner],
                configuration_resolution=(
                    "unavailable"
                    if status == "unavailable"
                    else (
                        "not-applicable"
                        if status == "not-applicable"
                        else ("failed" if status == "failed" else "live-service")
                    )
                ),
                advisory_database=(
                    "PyPI Advisory Database"
                    if scanner == "pip-audit"
                    else "OSV.dev"
                ),
                advisory_database_checked_at=self.database_checked_at[scanner],
                failure_detail=detail,
            ))
        return records

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
                ecosystem = info.get("ecosystem", "unknown")
                for vuln in pkg.get("vulnerabilities", []) or []:
                    vid = vuln.get("id", "UNKNOWN")
                    summary = (vuln.get("summary") or vuln.get("details") or "").strip()
                    out.append(CandidateFinding(
                        title=f"Vulnerable dependency {name} ({vid})",
                        file=manifest, line_start=1, line_end=1,
                        citation_snippet=f"{name}@{version} — {vid}",
                        identity_key=_identity(ecosystem, name, version, vid),
                        source_tool=self.tool_name, confidence=_SCA_CONFIDENCE,
                        producer="osv-scanner",
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
