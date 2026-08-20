"""Bounded OPT-010 exact-source and offline-instrument qualification helper.

This module is intentionally disconnected from the production pipeline and store.  It
materializes only receipt-frozen public commits, runs deterministic scanners without
persisting candidate identities, and emits aggregate/digest evidence beneath one isolated
artifact root.  The pip-audit path is deliberately restricted to direct exact pins and
always disables pip and dependency resolution.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..detect.deterministic import SastAdapter, ScaAdapter, SecretsAdapter
from ..detect.deterministic.provenance import supplemental_semgrep_provenance, tool_version
from ..detect.retrieval import RetrievalIndex
from ..sourcefiles import iter_source_files


PIP_AUDIT_VERSION = "pip-audit 2.10.1"
PIP_AUDIT_COMMAND = (
    "pip-audit",
    "--disable-pip",
    "--no-deps",
    "-r",
    "$MANIFEST",
    "-f",
    "json",
    "--progress-spinner",
    "off",
)
ACCEPTED_SCANNER_STATES = {"complete", "empty", "not-applicable"}
DIRECT_PIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*==[^=<>!~;\s\\]+$")
MAX_ADDITIONAL_BYTES = 21_474_816_000
MAX_REPOSITORY_SECONDS = 180 * 60
MAX_TOTAL_SECONDS = 890 * 60


@dataclass(frozen=True)
class Subject:
    order: int
    repository: str
    commit: str
    stable_identity: str
    language: str


SUBJECTS = (
    Subject(1, "unslothai/unsloth", "489fab4a71f83dd4e02a430f560884c3d052c575", "1a1517101c0f8ee6e27ab189961f246bd5f7a8a9e70c5e0cae75132ba12f3bdd", "Python"),
    Subject(2, "amruthpillai/reactive-resume", "dbbab6fd7610cf1472d0e0377fc0e966faf7acda", "3fca500d6ca3d5ce0c0547bd7055e448d46f39d8ad49ab770683d0631f63b4d6", "TypeScript"),
    Subject(3, "0xJacky/nginx-ui", "f1b8d846eab834daf6a95e30e3d02d329fdcb0d4", "3476b18f12ad5bdd4e7c89c0aa5249cb2d97e2f7697f73ac4ef4d052d6195378", "Go"),
    Subject(4, "theonedev/onedev", "89e2f09b7b0cd9682a32a8b4a1ed863f791570ea", "7808d7614a6ab1fe0f5d8ad3e16eaff4a44477cc2b7be4296ea2e7caa2dc181b", "Java"),
    Subject(5, "pglombardo/PasswordPusher", "c8fd1dc18fc55b570c2acc06ded6b37f05da6ee5", "a7f7b694aa9c4b90dc6ec650283ce10f25f214a52a0e1a280a0cd4b4ff9299bc", "Ruby"),
    Subject(6, "SinTan1729/chhoto-url", "7d36ccbd585bd326adfff45982bb0a4d760287c1", "5d499169e2daafc100b54798d3e12f43627130324ed98d438804ff2cbc3f6342", "Rust"),
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


def _run(command: list[str], *, cwd: Path | None = None, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env={**os.environ, "GIT_LFS_SKIP_SMUDGE": "1", "GIT_TERMINAL_PROMPT": "0"},
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def direct_pin_manifest(path: Path) -> tuple[bool, str | None]:
    """Accept only plain, active, exact ``name==version`` requirement lines."""
    for number, raw in enumerate(path.read_text(errors="replace").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if " #" in line:
            line = line.split(" #", 1)[0].rstrip()
        if not DIRECT_PIN.fullmatch(line):
            return False, f"unsupported direct-pin syntax at line {number}"
    return True, None


def _valid_pip_json(raw: str) -> tuple[bool, list[dict[str, Any]]]:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return False, []
    dependencies = parsed.get("dependencies", parsed) if isinstance(parsed, dict) else parsed
    if not isinstance(dependencies, list):
        return False, []
    return True, dependencies


def run_direct_pip_audit(manifest: Path, raw_output: Path, timeout: int = 180) -> dict[str, Any]:
    """Run exactly one no-pip/no-dependency-resolution audit."""
    valid, reason = direct_pin_manifest(manifest)
    version = tool_version("pip-audit", "--version", timeout_seconds=10)
    base = {
        "scanner": "pip-audit",
        "version": version,
        "invocation": list(PIP_AUDIT_COMMAND),
        "configuration": "PyPI vulnerability service",
        "configuration_resolution": "live-service",
        "dependency_resolution": False,
        "dependency_installation": False,
        "target_count_basis": "submitted-manifests",
    }
    if version != PIP_AUDIT_VERSION:
        return {**base, "status": "failed", "output_valid": False, "finding_count": 0, "target_count": 1, "failure_detail": "pip-audit version drift"}
    if not valid:
        return {**base, "status": "failed", "output_valid": False, "finding_count": 0, "target_count": 1, "failure_detail": reason}

    command = [manifest.as_posix() if item == "$MANIFEST" else item for item in PIP_AUDIT_COMMAND]
    try:
        completed = _run(command, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {**base, "status": "failed", "output_valid": False, "finding_count": 0, "target_count": 1, "failure_detail": f"{type(exc).__name__}: {exc}"[:300]}
    if completed.stdout:
        raw_output.parent.mkdir(parents=True, exist_ok=True)
        raw_output.write_text(completed.stdout, encoding="utf-8")
    output_valid, dependencies = _valid_pip_json(completed.stdout)
    if completed.returncode not in {0, 1} or not output_valid:
        return {**base, "status": "failed", "output_valid": False, "finding_count": 0, "target_count": 1, "failure_detail": "no valid JSON output from exact no-resolution invocation"}
    finding_count = sum(len(item.get("vulns", []) or []) for item in dependencies if isinstance(item, dict))
    return {
        **base,
        "status": "complete" if finding_count else "empty",
        "output_valid": True,
        "finding_count": finding_count,
        "target_count": 1,
        "advisory_database": "PyPI Advisory Database",
        "advisory_database_checked_at": _utc_now(),
        "failure_detail": None,
    }


def run_corrected_pip_canary(artifact_root: Path) -> dict[str, Any]:
    fixture = artifact_root / "pip-audit-canary-fixtures"
    fixture.mkdir(parents=True, exist_ok=False)
    positive = fixture / "positive.txt"
    clean = fixture / "clean.txt"
    positive.write_text("requests==2.19.1\n", encoding="utf-8")
    clean.write_text("# deliberately empty clean control\n", encoding="utf-8")
    positive_result = run_direct_pip_audit(positive, artifact_root / "pip-audit-canary-positive-raw.json")
    clean_result = run_direct_pip_audit(clean, artifact_root / "pip-audit-canary-clean-raw.json")
    passed = (
        positive_result["status"] == "complete"
        and positive_result["finding_count"] > 0
        and clean_result["status"] == "empty"
        and clean_result["finding_count"] == 0
    )
    report = {
        "schema_version": 1,
        "scanner": "pip-audit",
        "passed": passed,
        "positive": positive_result,
        "clean": clean_result,
        "persisted_findings": 0,
    }
    _write_json(artifact_root / "canary-pip-audit-direct.json", report)
    return report


def _snapshot_digest(root: Path) -> tuple[str, int, int]:
    digest = hashlib.sha256()
    count = 0
    total = 0
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] == ".git":
            continue
        if path.is_symlink():
            payload = b"L\0" + os.readlink(path).encode("utf-8", errors="surrogateescape")
        elif path.is_file():
            payload = b"F\0" + path.read_bytes()
        else:
            continue
        name = relative.as_posix().encode("utf-8", errors="surrogateescape")
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
        count += 1
        total += len(payload)
    return digest.hexdigest(), count, total


def _detector_input_digest(root: Path) -> tuple[str, int, int]:
    digest = hashlib.sha256()
    files = iter_source_files(root)
    total = 0
    for path in files:
        relative = path.relative_to(root).as_posix().encode()
        payload = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
        total += len(payload)
    return digest.hexdigest(), len(files), total


def _acquire(subject: Subject, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    operations = (
        (["git", "init", "--quiet"], 30),
        (["git", "remote", "add", "origin", f"https://github.com/{subject.repository}.git"], 30),
        (["git", "-c", "protocol.version=2", "fetch", "--quiet", "--depth=1", "--no-tags", "origin", subject.commit], 900),
        (["git", "checkout", "--quiet", "--detach", "FETCH_HEAD"], 300),
    )
    for command, timeout in operations:
        completed = _run(command, cwd=destination, timeout=timeout)
        if completed.returncode != 0:
            raise RuntimeError(f"exact acquisition failed at {command[1]}: {completed.stderr[:240]}")
    head = _run(["git", "rev-parse", "HEAD"], cwd=destination, timeout=30)
    if head.returncode != 0 or head.stdout.strip() != subject.commit:
        raise RuntimeError("materialized HEAD does not equal frozen commit")


def _semgrep_scan(snapshot: Path, output: Path, timeout: int) -> dict[str, Any]:
    adapter = SastAdapter(
        timeout,
        sarif_output_path=output / "semgrep.sarif",
        target_report_output_path=output / "semgrep-targets.json",
    )
    adapter.run(snapshot)
    return adapter.execution().model_dump(mode="json")


def _supplemental_scan(snapshot: Path, output: Path, timeout: int) -> dict[str, Any]:
    rules, digest, _ = supplemental_semgrep_provenance()
    adapter = SastAdapter(
        timeout,
        sarif_output_path=output / "semgrep-supplemental.sarif",
        target_report_output_path=output / "semgrep-supplemental-targets.json",
        configuration=str(rules),
        configuration_label=f"repoauditor-supplemental@sha256:{digest}",
        scanner_name="semgrep-supplemental",
        producer="semgrep-supplemental",
        applicable_extensions=frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}),
    )
    adapter.run(snapshot)
    return adapter.execution().model_dump(mode="json")


def _gitleaks_scan(snapshot: Path, _output: Path, timeout: int) -> dict[str, Any]:
    adapter = SecretsAdapter(timeout)
    adapter.run(snapshot)
    return adapter.execution().model_dump(mode="json")


def _pip_scan(snapshot: Path, output: Path, timeout: int) -> dict[str, Any]:
    manifests = sorted(path for path in snapshot.glob("requirements*.txt") if path.is_file())
    if not manifests:
        return {
            "scanner": "pip-audit",
            "status": "not-applicable",
            "applicable": False,
            "output_valid": True,
            "finding_count": 0,
            "target_count": 0,
            "target_count_basis": "not-applicable",
            "version": PIP_AUDIT_VERSION,
            "invocation": list(PIP_AUDIT_COMMAND),
            "configuration_resolution": "not-applicable",
            "applicability_detail": "snapshot contains no root-level requirements*.txt file",
            "dependency_resolution": False,
            "dependency_installation": False,
        }
    records = [
        run_direct_pip_audit(path, output / "pip-audit" / f"manifest-{index}.json", timeout)
        for index, path in enumerate(manifests, start=1)
    ]
    failures = [item for item in records if item["status"] == "failed"]
    if failures:
        return {
            **failures[0],
            "target_count": len(manifests),
            "failure_detail": failures[0]["failure_detail"],
        }
    findings = sum(item["finding_count"] for item in records)
    return {
        **records[0],
        "status": "complete" if findings else "empty",
        "finding_count": findings,
        "target_count": len(manifests),
    }


def _osv_scan(snapshot: Path, _output: Path, timeout: int) -> dict[str, Any]:
    adapter = ScaAdapter(timeout)
    adapter._run_osv_scanner(snapshot)
    return {
        item.scanner: item.model_dump(mode="json") for item in adapter.executions()
    }["osv-scanner"]


def _scan(snapshot: Path, output: Path, timeout: int = 150) -> list[dict[str, Any]]:
    output.mkdir(parents=True, exist_ok=False)
    jobs = (
        _semgrep_scan,
        _supplemental_scan,
        _gitleaks_scan,
        _pip_scan,
        _osv_scan,
    )
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = [pool.submit(job, snapshot, output, timeout) for job in jobs]
        return [future.result() for future in futures]


def _artifact_bytes(root: Path) -> int:
    return sum(path.stat().st_size for path in root.rglob("*") if path.is_file())


def _retrieval_summary(snapshot: Path) -> dict[str, Any]:
    index = RetrievalIndex().build(snapshot)
    functions = index._functions  # aggregate-only introspection of the frozen index
    return {
        "content_digest": index.content_digest(),
        "source_files": len(index._file_texts),
        "indexed_functions": len(functions),
        "language_modes": dict(sorted({
            language: sum(item.language == language for item in functions)
            for language in {item.language for item in functions}
        }.items())),
        "lexical_fallback_extensions": len(index._lexical_logged),
    }


def verifier_eligibility(subjects: list[dict[str, Any]]) -> dict[str, Any]:
    supported_languages = {"Python", "TypeScript", "Java", "Ruby"}
    supported = sum(item["language"] in supported_languages for item in subjects)
    return {
        "language_supported_subjects": supported,
        "language_unsupported_subjects": len(subjects) - supported,
        "mechanism_vocabulary_resolved_subjects": 0,
        "mechanism_vocabulary_unresolved_subjects": len(subjects),
        "fully_eligible_subjects": 0,
        "basis": "Frozen broad boundary hypotheses do not equal the verifier's concrete mechanism keys; no mechanism was inferred from scanner output.",
    }


def qualify(artifact_root: Path) -> dict[str, Any]:
    started = time.monotonic()
    summary: dict[str, Any] = {
        "schema_version": 1,
        "status": "running",
        "started_at": _utc_now(),
        "subjects": [],
        "logical_scanner_processes": 5,
        "repositories_materialized": 0,
        "retrieval_indexes_built": 0,
    }
    for subject in SUBJECTS:
        subject_started = time.monotonic()
        record: dict[str, Any] = {
            "order": subject.order,
            "stable_identity_sha256": subject.stable_identity,
            "language": subject.language,
            "exact_commit": subject.commit,
            "terminal_state": "failed",
        }
        summary["subjects"].append(record)
        subject_root = artifact_root / "subjects" / subject.stable_identity
        snapshot = subject_root / "snapshot"
        try:
            _acquire(subject, snapshot)
            summary["repositories_materialized"] += 1
            snapshot_sha, file_count, snapshot_bytes = _snapshot_digest(snapshot)
            detector_sha, source_count, detector_bytes = _detector_input_digest(snapshot)
            record.update({
                "snapshot_sha256": snapshot_sha,
                "snapshot_file_count": file_count,
                "snapshot_bytes": snapshot_bytes,
                "detector_input_sha256": detector_sha,
                "detector_source_file_count": source_count,
                "detector_input_bytes": detector_bytes,
                "architecture_map_sha256": "pending-separate-provider-authorization",
            })
            executions = _scan(snapshot, subject_root / "scanners")
            summary["logical_scanner_processes"] += 5
            record["scanner_executions"] = executions
            failed = [item for item in executions if item["status"] not in ACCEPTED_SCANNER_STATES]
            if failed:
                record["failure_stage"] = "scanner"
                record["failure_scanner"] = failed[0]["scanner"]
                record["failure_status"] = failed[0]["status"]
                raise RuntimeError("scanner inventory failed closed")
            record["retrieval"] = _retrieval_summary(snapshot)
            summary["retrieval_indexes_built"] += 1
            record["terminal_state"] = "completed"
        except Exception as exc:
            record.setdefault("failure_stage", "acquisition-or-qualification")
            record["failure_class"] = type(exc).__name__
            record["failure_detail"] = str(exc)[:300]
            summary["status"] = "stopped"
        record["elapsed_seconds"] = round(time.monotonic() - subject_started, 3)
        if record["elapsed_seconds"] > MAX_REPOSITORY_SECONDS:
            record["terminal_state"] = "timed_out"
            summary["status"] = "stopped"
        summary["new_data_bytes"] = _artifact_bytes(artifact_root)
        if summary["new_data_bytes"] > MAX_ADDITIONAL_BYTES:
            record["terminal_state"] = "budget_exhausted"
            summary["status"] = "stopped"
        if time.monotonic() - started > MAX_TOTAL_SECONDS:
            record["terminal_state"] = "budget_exhausted"
            summary["status"] = "stopped"
        _write_json(artifact_root / "execution-summary.json", summary)
        if summary["status"] == "stopped":
            break
    if summary["status"] != "stopped":
        summary["status"] = "complete"
    summary["verifier_eligibility"] = verifier_eligibility(summary["subjects"])
    summary["finished_at"] = _utc_now()
    summary["elapsed_seconds"] = round(time.monotonic() - started, 3)
    summary["new_data_bytes"] = _artifact_bytes(artifact_root)
    _write_json(artifact_root / "execution-summary.json", summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("pip-canary", "qualify"))
    parser.add_argument("--artifact-root", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "pip-canary":
        result = run_corrected_pip_canary(args.artifact_root)
    else:
        result = qualify(args.artifact_root)
    print(json.dumps({
        "status": result.get("status", "passed" if result.get("passed") else "failed"),
        "passed": result.get("passed"),
    }, sort_keys=True))
    if result.get("passed") is False or result.get("status") == "stopped":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
