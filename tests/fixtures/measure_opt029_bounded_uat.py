"""Measure the frozen OPT-029 funnel over a retained bounded-UAT raw report."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

from repoauditor.triage.acquisition_funnel import (
    AcquisitionFunnelCounts,
    AcquisitionIdentityInput,
    ReviewPathTier,
    classify_review_path,
    exact_location_identity,
    pre_post_identity,
    repeated_family_identity,
    review_path_tier,
)


def _digest(*values: object) -> str:
    payload = "\x1f".join(str(value) for value in values)
    return hashlib.sha256(payload.encode()).hexdigest()


def _identity(record: dict) -> AcquisitionIdentityInput:
    candidate = record["candidate"]
    return AcquisitionIdentityInput(
        engagement=record["repo_id"],
        producer=candidate["producer"],
        rule_id=candidate["title"],
        file=candidate["file"],
        line_start=candidate["line_start"],
        line_end=candidate["line_end"],
        sink=candidate["citation_snippet"],
    )


def _ordered(records: list[dict]) -> list[dict]:
    return sorted(records, key=lambda record: _digest(
        "candidate",
        record["repo_id"],
        repr(exact_location_identity(_identity(record))),
    ))


def measure(report: dict, *, limit: int, max_per_engagement: int) -> dict:
    records = [
        {
            "repo_id": result["repo_id"],
            "project_id": result["project_id"],
            "variant": result["variant"],
            "candidate": candidate,
        }
        for result in report["results"]
        for candidate in result["candidates"]
    ]
    raw = len(records)
    by_project: dict[str, dict[str, set[tuple[object, ...]]]] = defaultdict(
        lambda: defaultdict(set)
    )
    for record in records:
        if record["variant"] in {"pre_fix", "post_fix"}:
            by_project[record["project_id"]][record["variant"]].add(
                pre_post_identity(_identity(record))
            )
    after_pre_post = [
        record
        for record in records
        if not (
            record["variant"] == "post_fix"
            and pre_post_identity(_identity(record))
            in by_project[record["project_id"]]["pre_fix"]
        )
    ]
    exact_groups: dict[tuple[object, ...], list[dict]] = defaultdict(list)
    for record in after_pre_post:
        exact_groups[exact_location_identity(_identity(record))].append(record)
    after_exact = [
        _ordered(group)[0]
        for _, group in sorted(exact_groups.items(), key=lambda item: repr(item[0]))
    ]
    path_classes = Counter(
        classify_review_path(record["candidate"]["file"]).value
        for record in after_exact
    )
    after_path = [
        record
        for record in after_exact
        if review_path_tier(
            classify_review_path(record["candidate"]["file"])
        ) is not ReviewPathTier.DEFERRED
    ]
    family_groups: dict[tuple[str, ...], list[dict]] = defaultdict(list)
    for record in after_path:
        family_groups[repeated_family_identity(_identity(record))].append(record)
    family_counts = {
        _digest("family", *identity): len(group)
        for identity, group in sorted(family_groups.items())
    }
    after_family = [
        record
        for group in family_groups.values()
        for record in _ordered(group)[:2]
    ]
    by_engagement: dict[str, list[dict]] = defaultdict(list)
    for record in after_family:
        by_engagement[record["repo_id"]].append(record)
    balanced = [
        record
        for engagement in sorted(by_engagement)
        for record in _ordered(by_engagement[engagement])[:max_per_engagement]
    ]
    selected = _ordered(balanced)[:limit]
    funnel = AcquisitionFunnelCounts(
        raw=raw,
        after_pre_post_collapse=len(after_pre_post),
        after_exact_duplicate_collapse=len(after_exact),
        after_path_policy=len(after_path),
        after_family_cap=len(after_family),
        after_engagement_balance=len(balanced),
        selected=len(selected),
    )
    return {
        "schema_version": "opt-029-bounded-uat-replay-v1",
        "selection_policy": {
            "limit": limit,
            "max_per_engagement": max_per_engagement,
            "max_per_family_per_engagement": 2,
            "included_path_tiers": [
                ReviewPathTier.PRIMARY.value,
                ReviewPathTier.SUPPORTING.value,
            ],
        },
        "input_digest": _digest(*(
            repr(exact_location_identity(_identity(record)))
            for record in sorted(
                records,
                key=lambda item: (
                    item["repo_id"],
                    repr(exact_location_identity(_identity(item))),
                ),
            )
        )),
        "funnel": {
            "counts": {
                "raw": funnel.raw,
                "after_pre_post_collapse": funnel.after_pre_post_collapse,
                "after_exact_duplicate_collapse": (
                    funnel.after_exact_duplicate_collapse
                ),
                "after_path_policy": funnel.after_path_policy,
                "after_family_cap": funnel.after_family_cap,
                "after_engagement_balance": funnel.after_engagement_balance,
                "selected": funnel.selected,
            },
            "deferred_by_stage": funnel.deferred_by_stage(),
        },
        "path_class_counts_after_exact_collapse": dict(sorted(path_classes.items())),
        "family_counts_before_cap": family_counts,
        "selected_identity_hashes": [
            _digest("selected", repr(exact_location_identity(_identity(record))))
            for record in selected
        ],
        "ground_truth_used": False,
        "candidate_outcomes_used": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=32)
    parser.add_argument("--max-per-engagement", type=int, default=4)
    args = parser.parse_args()
    raw = args.input.read_bytes()
    report = json.loads(raw)
    result = measure(
        report,
        limit=args.limit,
        max_per_engagement=args.max_per_engagement,
    )
    result["raw_artifact"] = {
        "path": str(args.input),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "retained_outside_git": True,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result["funnel"], sort_keys=True))


if __name__ == "__main__":
    main()
