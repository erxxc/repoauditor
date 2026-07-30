"""Execute the frozen OPT-027/028 Semgrep qualification without persisting findings."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from repoauditor.detect.deterministic import SastAdapter
from repoauditor.detect.deterministic.provenance import (
    SEMGREP_CONFIGURATION,
    supplemental_semgrep_provenance,
)
from repoauditor.eval.scanner_differential import (
    AdvisoryTargetSpec,
    DifferentialClassification,
    classify_advisory_pair,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
PROTOCOL_PATH = (
    REPO_ROOT
    / "docs"
    / "optimizations"
    / "opt-027-028-supplemental-differential-protocol-2026-07-29.json"
)
RULE_ID = "repoauditor.javascript.security.dynamic-shell-execution"


def tree_digest(snapshot: Path) -> str:
    """Match the frozen portable shasum-of-relative-file-hashes construction."""
    lines = []
    paths = (
        item
        for item in snapshot.rglob("*")
        if item.is_file() and not item.is_symlink()
    )
    for path in sorted(paths, key=lambda item: item.relative_to(snapshot).as_posix()):
        if "__pycache__" in path.parts:
            continue
        relative = path.relative_to(snapshot).as_posix()
        lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  ./{relative}\n")
    return hashlib.sha256("".join(lines).encode()).hexdigest()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _resolve_protocol_path(value: str) -> Path:
    return (PROTOCOL_PATH.parent / value).resolve()


def _candidate_identity(candidate) -> tuple[str, str, str, int, int, str, str]:
    return (
        candidate.producer or candidate.source_tool,
        candidate.source_tool,
        candidate.file.replace("\\", "/").lstrip("./"),
        candidate.line_start,
        candidate.line_end,
        candidate.title,
        candidate.citation_snippet,
    )


def _candidate_deltas(pre_candidates, post_candidates) -> dict[str, int]:
    pre = {_candidate_identity(candidate) for candidate in pre_candidates}
    post = {_candidate_identity(candidate) for candidate in post_candidates}
    return {
        "pre_candidate_count": len(pre),
        "post_candidate_count": len(post),
        "stable_candidate_count": len(pre & post),
        "pre_only_candidate_count": len(pre - post),
        "post_only_candidate_count": len(post - pre),
    }


def _run_adapter(
    *,
    snapshot: Path,
    artifact_root: Path,
    supplemental: bool,
    timeout_seconds: int,
) -> tuple[SastAdapter, list]:
    artifact_root.mkdir(parents=True, exist_ok=True)
    if supplemental:
        rules, digest, _ = supplemental_semgrep_provenance()
        adapter = SastAdapter(
            timeout_seconds,
            sarif_output_path=artifact_root / "semgrep-supplemental.sarif",
            target_report_output_path=artifact_root / "semgrep-supplemental-targets.json",
            configuration=str(rules),
            configuration_label=f"repoauditor-supplemental@sha256:{digest}",
            scanner_name="semgrep-supplemental",
            producer="semgrep-supplemental",
            applicable_extensions=frozenset({
                ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
            }),
        )
    else:
        adapter = SastAdapter(
            timeout_seconds,
            sarif_output_path=artifact_root / "semgrep.sarif",
            target_report_output_path=artifact_root / "semgrep-targets.json",
            configuration=SEMGREP_CONFIGURATION,
        )
    return adapter, adapter.run(snapshot)


def _execution_record(adapter: SastAdapter, artifact_root: Path) -> dict:
    execution = adapter.execution().model_dump(mode="json")
    stem = "semgrep-supplemental" if adapter.scanner_name.endswith("supplemental") else "semgrep"
    sarif = artifact_root / f"{stem}.sarif"
    targets = artifact_root / f"{stem}-targets.json"
    execution["sarif_artifact"] = sarif.relative_to(REPO_ROOT).as_posix()
    execution["sarif_sha256"] = _sha256(sarif)
    execution["target_report_artifact"] = (
        targets.relative_to(REPO_ROOT).as_posix() if targets.is_file() else None
    )
    execution["target_report_sha256"] = _sha256(targets) if targets.is_file() else None
    return execution


def _control_results(manifest: dict, candidates: list) -> list[dict]:
    results = []
    for case in manifest["cases"]:
        matches = [
            candidate
            for candidate in candidates
            if candidate.title == manifest["rule_id"]
            and candidate.file.replace("\\", "/").lstrip("./") == case["file"]
            and candidate.line_start <= case["line_end"]
            and candidate.line_end >= case["line_start"]
        ]
        observed = "raised" if matches else "absent"
        results.append({
            "id": case["id"],
            "expected": case["expected_detection"],
            "observed": observed,
            "passed": observed == case["expected_detection"],
            "match_count": len(matches),
        })
    return results


def run_qualification(
    *,
    raw_root: Path,
    canary_report: Path,
    timeout_seconds: int,
) -> dict:
    protocol = json.loads(PROTOCOL_PATH.read_text())
    canary = json.loads(canary_report.read_text())
    if not canary.get("passed") or canary.get("persisted_findings") != 0:
        raise RuntimeError("frozen deployment canary did not pass cleanly")

    rules, supplemental_digest, supplemental_rule_count = (
        supplemental_semgrep_provenance()
    )
    control = protocol["manufactured_controls"]
    control_snapshot = _resolve_protocol_path(control["snapshot"])
    if tree_digest(control_snapshot) != control["snapshot_tree_sha256"]:
        raise RuntimeError("manufactured control snapshot digest changed")
    control_manifest = json.loads(
        _resolve_protocol_path(control["manifest"]).read_text()
    )
    control_root = raw_root / "controls"
    control_adapter, control_candidates = _run_adapter(
        snapshot=control_snapshot,
        artifact_root=control_root,
        supplemental=True,
        timeout_seconds=timeout_seconds,
    )
    controls = _control_results(control_manifest, control_candidates)

    pair_results = []
    codecov_classification = None
    for pair in protocol["frozen_acquisition_pairs"]:
        variants = {}
        candidates = {}
        for variant in ("pre", "post"):
            snapshot = _resolve_protocol_path(pair[f"{variant}_fixture"])
            expected_digest = pair[f"{variant}_tree_sha256"]
            observed_digest = tree_digest(snapshot)
            if observed_digest != expected_digest:
                raise RuntimeError(
                    f"{pair['slug']} {variant} snapshot digest changed"
                )
            variant_root = raw_root / pair["slug"] / variant
            official, official_candidates = _run_adapter(
                snapshot=snapshot,
                artifact_root=variant_root,
                supplemental=False,
                timeout_seconds=timeout_seconds,
            )
            supplemental, supplemental_candidates = _run_adapter(
                snapshot=snapshot,
                artifact_root=variant_root,
                supplemental=True,
                timeout_seconds=timeout_seconds,
            )
            variants[variant] = {
                "commit": pair[f"{variant}_commit"],
                "snapshot_tree_sha256": observed_digest,
                "official_execution": _execution_record(official, variant_root),
                "supplemental_execution": _execution_record(
                    supplemental, variant_root
                ),
            }
            candidates[variant] = {
                "official": official_candidates,
                "supplemental": supplemental_candidates,
            }

        result = {
            "slug": pair["slug"],
            "role": pair["role"],
            "pre": variants["pre"],
            "post": variants["post"],
            "official_candidate_deltas": _candidate_deltas(
                candidates["pre"]["official"],
                candidates["post"]["official"],
            ),
            "supplemental_candidate_deltas": _candidate_deltas(
                candidates["pre"]["supplemental"],
                candidates["post"]["supplemental"],
            ),
            "advisory_target_classification": None,
        }
        if pair["role"] == "declared_rule_qualification_target":
            target = AdvisoryTargetSpec(
                file=pair["target_file"],
                rule_ids=(RULE_ID,),
                citation_contains=pair["target_citation_contains"],
                line_start=pair["target_line_start"],
                line_end=pair["target_line_end"],
            )
            differential = classify_advisory_pair(
                pre_candidates=candidates["pre"]["supplemental"],
                post_candidates=candidates["post"]["supplemental"],
                target=target,
            )
            result["advisory_target_classification"] = differential.model_dump(
                mode="json"
            )
            codecov_classification = differential.classification
        pair_results.append(result)

    executions = [
        variant[f"{scanner}_execution"]
        for pair in pair_results
        for variant in (pair["pre"], pair["post"])
        for scanner in ("official", "supplemental")
    ]
    promoted = (
        all(result["passed"] for result in controls)
        and codecov_classification
        is DifferentialClassification.VULNERABLE_ONLY_RECOVERY
        and all(
            execution["status"] in {"complete", "empty", "not-applicable"}
            and (
                execution["status"] == "not-applicable"
                or (execution["output_valid"] and execution["target_count"] > 0)
            )
            and execution["configuration_resolution"] == "pinned-verified"
            for execution in executions
        )
    )
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "optimizations": ["OPT-027", "OPT-028"],
        "protocol": PROTOCOL_PATH.relative_to(REPO_ROOT).as_posix(),
        "status": "qualified" if promoted else "qualification-failed",
        "prior_failed_attempt": {
            "artifact": (
                "docs/optimizations/"
                "opt-027-028-supplemental-differential-attempt-1-2026-07-29.json"
            ),
            "sha256": "a606415bb932f3c93d8cae1d1aeeec0761e3ac4f357921de4f60a682ff967287",
            "reason": (
                "The initial qualification correctly failed promotion because the "
                "supplemental adapter classified language-inapplicable Python and Ruby "
                "snapshots as failed zero-target runs rather than not-applicable."
            )
        },
        "selection_changed_after_results": False,
        "deployment_canary": {
            "passed": True,
            "persisted_findings": 0,
            "artifact": canary_report.relative_to(REPO_ROOT).as_posix(),
            "sha256": _sha256(canary_report),
        },
        "supplemental_ruleset": {
            "path": rules.relative_to(REPO_ROOT).as_posix(),
            "sha256": supplemental_digest,
            "rule_count": supplemental_rule_count,
            "rule_id": RULE_ID,
        },
        "manufactured_controls": {
            "execution": _execution_record(control_adapter, control_root),
            "results": controls,
            "passed": all(result["passed"] for result in controls),
        },
        "pairs": pair_results,
        "promotion": {
            "criteria_passed": promoted,
            "production_integration_enabled": promoted,
        },
        "isolation": {
            "automatic_labels_added": 0,
            "ground_truth_changes": 0,
            "classifier_scoring_changes": 0,
            "review_pool_candidates_added": 0,
            "raw_candidates_adjudicated": False,
        },
        "interpretation": (
            "Qualification covers one owned dynamic shell-execution rule. Matches remain "
            "review candidates; observational non-target pairs make no advisory-recovery "
            "claim, and unrelated candidates remain unadjudicated."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-root", type=Path, required=True)
    parser.add_argument("--canary-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args()
    result = run_qualification(
        raw_root=args.raw_root.resolve(),
        canary_report=args.canary_report.resolve(),
        timeout_seconds=args.timeout_seconds,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({
        "status": result["status"],
        "controls_passed": result["manufactured_controls"]["passed"],
        "pair_count": len(result["pairs"]),
    }, sort_keys=True))
    if result["status"] != "qualified":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
