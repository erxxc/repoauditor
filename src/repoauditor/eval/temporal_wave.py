"""Freeze and reuse one pre-outcome classifier for an OPT-003 prediction wave."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import joblib

from ..config import get_config
from ..store import db
from ..triage import training
from ..triage.classifier import TriageClassifier, triage_repo
from ..triage.families import evaluation_family, family_distinct_labels


EXPECTED_STORE_SHA256 = "d34e2ff9bf8946209686c47a15ed4428ada11c1b08afc05705be8b7adb3107eb"
EXPECTED_LABEL_SHA256 = "b56131b57e949fb8512773bc28cedfae56f598bf2a9ae233088e9d3726202d87"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def effective_label_digest() -> tuple[int, str]:
    config = get_config()
    labels = family_distinct_labels(db.list_triage_labels(config=config), config)
    rows = [
        (evaluation_family(item.engagement, config), item.rule_id,
         item.finding_fingerprint, item.actionable, str(item.source), item.created_at)
        for item in labels
    ]
    encoded = json.dumps(sorted(rows), separators=(",", ":")).encode()
    return len(rows), hashlib.sha256(encoded).hexdigest()


def freeze_model(output: Path, metadata: Path) -> None:
    config = get_config()
    if _sha256(config.db_path) != EXPECTED_STORE_SHA256:
        raise RuntimeError("persistent store digest drifted before wave training")
    count, digest = effective_label_digest()
    if (count, digest) != (122, EXPECTED_LABEL_SHA256):
        raise RuntimeError("effective training-label identity drifted")
    if output.exists() or metadata.exists():
        raise RuntimeError("refusing to overwrite frozen wave model")
    corpus = training.assemble_training_data(config, seed=0)
    classifier = TriageClassifier.train(
        corpus.X, corpus.y, seed=0, sample_weight=corpus.sample_weight,
        real_mask=corpus.real_mask, engagement_groups=corpus.engagement_groups,
        evaluation_mask=corpus.evaluation_mask,
        min_real_holdout=config.triage.min_real_labels_for_holdout_eval,
    )
    classifier._explainer = None
    output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(classifier, output)
    metadata.write_text(json.dumps({
        "effective_labels": count,
        "effective_label_sha256": digest,
        "model_name": classifier.model_name,
        "model_sha256": _sha256(output),
        "evaluations": [item.__dict__ for item in classifier.evaluations],
    }, indent=2) + "\n", encoding="utf-8")


def score_repo(model: Path, repo_id: str, sarif: Path) -> None:
    count, digest = effective_label_digest()
    if (count, digest) != (122, EXPECTED_LABEL_SHA256):
        raise RuntimeError("labels changed after wave model freeze")
    classifier: TriageClassifier = joblib.load(model)
    classifier._build_explainer()
    triage_repo(repo_id, get_config(), sarif_path=sarif, classifier=classifier)
    after = effective_label_digest()
    if after != (count, digest):
        raise RuntimeError("scoring changed the frozen label corpus")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    freeze = sub.add_parser("freeze")
    freeze.add_argument("--output", type=Path, required=True)
    freeze.add_argument("--metadata", type=Path, required=True)
    score = sub.add_parser("score")
    score.add_argument("--model", type=Path, required=True)
    score.add_argument("--repo-id", required=True)
    score.add_argument("--sarif", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "freeze":
        freeze_model(args.output, args.metadata)
    else:
        score_repo(args.model, args.repo_id, args.sarif)


if __name__ == "__main__":
    main()
