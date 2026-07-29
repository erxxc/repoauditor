"""Run the bounded, scanner-only public-corpus UAT and write structured evidence.

The independent corpus has one human-reviewed historical CVE target per project; it is
not an exhaustive inventory of every vulnerability in each repository. Consequently this
runner reports target detection and post-fix target persistence, but never mislabels every
other scanner candidate as a false positive. Those candidates remain explicitly
unadjudicated until an analyst reviews them.

Acquired source is passed only to the existing deterministic adapters. It is never imported
or executed by this runner, and no hosted-model client is constructed.
"""

from __future__ import annotations

import argparse
import json
import shutil
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from repoauditor.detect.deterministic import SastAdapter, ScaAdapter, SecretsAdapter
from repoauditor.detect.ensemble import CandidateFinding


PILOT_FIXTURE_IDS = (
    "independent_django_pre",
    "independent_django_post",
    "independent_lodash_pre",
    "independent_lodash_post",
    "independent_commons_text_pre",
    "independent_commons_text_post",
    "independent_rack_pre",
    "independent_rack_post",
    "anchor_owasp_juice_shop",
)
REQUIRED_BINARIES = ("semgrep", "pip-audit", "osv-scanner", "gitleaks")


def _target_match(candidate: CandidateFinding, target: dict) -> str | None:
    """Return the evidence basis when a candidate points at the reviewed target."""
    if Path(candidate.file).as_posix() != Path(target["file"]).as_posix():
        return None
    needle = target.get("citation_contains")
    if needle and needle in candidate.citation_snippet:
        return "file+citation"
    target_line = int(target.get("line_start", 0))
    if target_line and candidate.line_start <= target_line <= candidate.line_end:
        return "file+line"
    cve = target.get("cve")
    searchable = f"{candidate.title} {candidate.citation_snippet} {candidate.rationale or ''}"
    if cve and cve in searchable:
        return "file+cve"
    return None


def evaluate_candidates(
    *, repo_id: str, expected: dict, candidates: list[CandidateFinding],
) -> dict:
    """Summarize target signals without claiming exhaustive-project precision."""
    source = expected["source"]
    targets = expected.get("findings") or expected.get("expected_absent", [])
    target_signals = []
    matched_candidate_indexes: set[int] = set()
    for target in targets:
        matches = []
        for index, candidate in enumerate(candidates):
            basis = _target_match(candidate, target)
            if basis:
                matched_candidate_indexes.add(index)
                matches.append({
                    "producer": candidate.producer or candidate.source_tool,
                    "file": candidate.file,
                    "line_start": candidate.line_start,
                    "line_end": candidate.line_end,
                    "title": candidate.title,
                    "match_basis": basis,
                })
        target_signals.append({
            "title": target["title"],
            "cve": target.get("cve"),
            "file": target["file"],
            "detected": bool(matches),
            "matches": matches,
        })

    variant = source.get("variant", "known_positive_anchor")
    return {
        "repo_id": repo_id,
        "project_id": source["project_id"],
        "project": source["project"],
        "language": source.get("language", "TypeScript" if source["project_id"] == "owasp_juice_shop" else "unknown"),
        "kind": source["kind"],
        "variant": variant,
        "pinned_commit": source["pinned_commit"],
        "target_signals": target_signals,
        "target_detected_count": sum(signal["detected"] for signal in target_signals),
        "target_count": len(target_signals),
        "patched_target_reappeared": (
            variant == "post_fix" and any(signal["detected"] for signal in target_signals)
        ),
        "candidate_count_by_producer": dict(sorted(Counter(
            candidate.producer or candidate.source_tool for candidate in candidates
        ).items())),
        "unadjudicated_candidate_count": len(candidates) - len(matched_candidate_indexes),
        "candidates": [
            {
                "producer": candidate.producer or candidate.source_tool,
                "source_tool": candidate.source_tool,
                "title": candidate.title,
                "file": candidate.file,
                "line_start": candidate.line_start,
                "line_end": candidate.line_end,
                "severity": candidate.severity.value,
                "confidence": candidate.confidence,
                "citation_snippet": candidate.citation_snippet,
            }
            for candidate in candidates
        ],
    }


def run_fixture(
    fixture_root: Path,
    repo_id: str,
    timeout_seconds: int,
    adapter_factories: tuple[Callable[[], object], ...] | None = None,
) -> dict:
    fixture = fixture_root / repo_id
    snapshot = fixture / "snapshot"
    if not snapshot.is_dir():
        raise RuntimeError(f"{repo_id} is not materialized at {snapshot}")
    expected = json.loads((fixture / "expected_findings.json").read_text())
    factories = adapter_factories or (
        lambda: SastAdapter(timeout_seconds),
        lambda: ScaAdapter(timeout_seconds),
        lambda: SecretsAdapter(timeout_seconds),
    )
    candidates: list[CandidateFinding] = []
    scanner_run_statuses: dict[str, str] = {}
    scanner_failure_details: dict[str, str] = {}
    for factory in factories:
        adapter = factory()
        candidates.extend(adapter.run(snapshot))
        tool_name = getattr(adapter, "tool_name", "unknown")
        if tool_name == "sca":
            scanner_run_statuses.update(adapter.run_statuses)
            scanner_failure_details.update(adapter.failure_details)
        else:
            producer = "semgrep" if tool_name == "sast" else "gitleaks"
            scanner_run_statuses[producer] = (
                getattr(adapter, "run_status", None) or "unknown"
            )
            failure = getattr(adapter, "failure_detail", None)
            if failure:
                scanner_failure_details[producer] = failure
    result = evaluate_candidates(repo_id=repo_id, expected=expected, candidates=candidates)
    result["semgrep_run_status"] = scanner_run_statuses.get("semgrep", "not-observed")
    result["scanner_run_statuses"] = dict(sorted(scanner_run_statuses.items()))
    result["scanner_failure_details"] = dict(sorted(scanner_failure_details.items()))
    return result


def _candidate_identity(candidate: dict) -> tuple:
    return (
        candidate["producer"], candidate["source_tool"], candidate["file"],
        candidate["line_start"], candidate["line_end"], candidate["title"],
        candidate["citation_snippet"],
    )


def build_pair_deltas(results: list[dict]) -> list[dict]:
    """Collapse unchanged pre/post signals without discarding either raw record."""
    projects: dict[str, dict[str, dict]] = {}
    for row in results:
        if row["variant"] in {"pre_fix", "post_fix"}:
            projects.setdefault(row["project_id"], {})[row["variant"]] = row
    deltas = []
    for project_id, variants in sorted(projects.items()):
        if set(variants) != {"pre_fix", "post_fix"}:
            continue
        pre = {_candidate_identity(candidate) for candidate in variants["pre_fix"]["candidates"]}
        post = {_candidate_identity(candidate) for candidate in variants["post_fix"]["candidates"]}
        deltas.append({
            "project_id": project_id,
            "pre_fix_candidate_count": len(pre),
            "post_fix_candidate_count": len(post),
            "stable_candidate_count": len(pre & post),
            "pre_fix_only_candidate_count": len(pre - post),
            "post_fix_only_candidate_count": len(post - pre),
            "pair_collapsed_candidate_count": len(pre | post),
        })
    return deltas


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", type=Path, default=Path(__file__).parent)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args()

    availability = {binary: shutil.which(binary) is not None for binary in REQUIRED_BINARIES}
    missing = [binary for binary, available in availability.items() if not available]
    if missing:
        raise SystemExit(f"required scanner binaries are missing: {', '.join(missing)}")

    results = [
        run_fixture(args.fixtures, repo_id, args.timeout_seconds)
        for repo_id in PILOT_FIXTURE_IDS
    ]
    pair_deltas = build_pair_deltas(results)
    anchors = [row for row in results if row["variant"] == "known_positive_anchor"]
    document = {
        "schema_version": 2,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "deterministic-scanners",
        "methodology": (
            "One reviewed CVE target per independent project; unmatched candidates are "
            "unadjudicated and are not counted as false positives."
        ),
        "scanner_binary_availability": availability,
        "summary": {
            "fixture_count": len(results),
            "pre_fix_targets_detected": sum(
                row["target_detected_count"] for row in results if row["variant"] == "pre_fix"
            ),
            "pre_fix_target_count": sum(
                row["target_count"] for row in results if row["variant"] == "pre_fix"
            ),
            "post_fix_target_persistence_count": sum(
                row["patched_target_reappeared"] for row in results
            ),
            "unadjudicated_candidate_count": sum(
                row["unadjudicated_candidate_count"] for row in results
            ),
            "raw_candidate_count": sum(len(row["candidates"]) for row in results),
            "pair_collapsed_candidate_count": (
                sum(row["pair_collapsed_candidate_count"] for row in pair_deltas)
                + sum(len(row["candidates"]) for row in anchors)
            ),
            "semgrep_run_statuses": dict(sorted(Counter(
                row["semgrep_run_status"] for row in results
            ).items())),
            "scanner_run_statuses": {
                scanner: dict(sorted(Counter(
                    row["scanner_run_statuses"].get(scanner, "not-observed")
                    for row in results
                ).items()))
                for scanner in ("semgrep", "gitleaks", "pip-audit", "osv-scanner")
            },
        },
        "pair_deltas": pair_deltas,
        "results": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2) + "\n")
    print(json.dumps(document["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
