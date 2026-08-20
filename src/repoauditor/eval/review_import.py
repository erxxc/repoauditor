"""Digest-checked, atomic importer for the frozen OPT-002 human review."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from ..config import get_config
from ..store import db
from ..store.models import TriageAssessment, TriageDisposition, TriageLabel, TriageLabelSource


EXPECTED_RESULT_SHA256 = "7479b805240ddfdd19f34e5853a7686ce618ed20ecbf986f656dd74f29e3a54a"
EXPECTED_STORE_SHA256 = "1f67635eb1458b93c3b9056f08377839f23d0726b0f3b92764f5791d2ca503b8"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def import_review(result_path: Path) -> dict:
    if _sha256(result_path) != EXPECTED_RESULT_SHA256:
        raise RuntimeError("bounded-review result digest drifted")
    config = get_config()
    if _sha256(config.db_path) != EXPECTED_STORE_SHA256:
        raise RuntimeError("persistent store digest drifted")
    payload = json.loads(result_path.read_text(encoding="utf-8"))
    responses = payload["responses"]
    if len(responses) != 12 or len({row["finding_id"] for row in responses}) != 12:
        raise RuntimeError("review result must contain 12 unique responses")

    features = {row.finding_id: row for row in db.list_triage_features(config)}
    assessments: list[TriageAssessment] = []
    labels: list[TriageLabel] = []
    for row in responses:
        disposition = TriageDisposition(row["disposition"])
        feature = features.get(row["finding_id"])
        if feature is None:
            raise RuntimeError(f"finding {row['finding_id']} lacks triage features")
        dimensions = [f"{key}: {value}" for key, value in row["verified_dimensions"].items()]
        assessment = TriageAssessment(
            finding_id=row["finding_id"], engagement=feature.engagement,
            outcome=disposition.outcome, disposition=disposition,
            rationale=row["rationale"], analyst="project owner", dimensions=dimensions,
            material=False, classifier_eligible=True,
        )
        assessments.append(assessment)
        if disposition is not TriageDisposition.INSUFFICIENT_EVIDENCE:
            labels.append(TriageLabel(
                engagement=feature.engagement, rule_id=feature.rule_id,
                finding_fingerprint=feature.fingerprint,
                actionable=disposition.outcome.value == "true_positive",
                note=row["rationale"], source=TriageLabelSource.MANUAL,
            ))
    if len(labels) != 11:
        raise RuntimeError("review result must project exactly 11 labels")
    assessment_ids, label_ids = db.import_triage_review_batch(assessments, labels, config)
    return {
        "assessment_ids": assessment_ids,
        "label_ids": label_ids,
        "assessment_count": len(assessment_ids),
        "label_count": len(label_ids),
        "abstention_count": 1,
        "store_sha256_after": _sha256(config.db_path),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise RuntimeError(f"refusing to overwrite {args.output}")
    outcome = import_review(args.result)
    args.output.write_text(json.dumps(outcome, indent=2) + "\n", encoding="utf-8")
    print(f"atomically imported {outcome['assessment_count']} assessments and {outcome['label_count']} labels")


if __name__ == "__main__":
    main()
