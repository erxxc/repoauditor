"""Ground-truth-blind acquisition plans for the next human triage tranche."""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

from ..config import Config, get_config
from ..store import db
from ..store.models import TriageLabelSource


@dataclass(frozen=True)
class ReviewAcquisitionCandidate:
    finding_id: int
    engagement: str
    rule_id: str
    fingerprint: str
    title: str
    file: str
    line: int
    prior_human_labels_for_rule: int
    selection_hash: str


@dataclass(frozen=True)
class ReviewAcquisitionPlan:
    schema_version: str
    selection_policy: str
    evaluation_eligible: bool
    requested_limit: int
    max_per_engagement: int
    max_prior_human_labels_per_rule: int
    existing_human_labels: int
    available_unassessed: int
    eligible_after_rule_cap: int
    entries: tuple[ReviewAcquisitionCandidate, ...]
    limitations: tuple[str, ...]


def build_review_acquisition_plan(
    config: Config | None = None,
    *,
    limit: int = 32,
    max_per_engagement: int = 4,
    max_prior_human_labels_per_rule: int = 5,
) -> ReviewAcquisitionPlan:
    """Select a stable, rule-diverse training-acquisition tranche.

    Prior human-label counts affect rule-family ordering, but no candidate score, predicted
    class, finding severity, falsification verdict, or code outcome enters selection.
    """
    if limit <= 0:
        raise ValueError("acquisition limit must be positive")
    if max_per_engagement <= 0:
        raise ValueError("max_per_engagement must be positive")
    if max_prior_human_labels_per_rule < 0:
        raise ValueError("max_prior_human_labels_per_rule cannot be negative")
    config = config or get_config()
    labels = [
        label
        for label in db.list_triage_labels(config=config)
        if label.source in {
            TriageLabelSource.MANUAL,
            TriageLabelSource.DERIVED_REVIEW,
        }
    ]
    labelled_keys = {
        (label.engagement, label.finding_fingerprint) for label in labels
    }
    assessed_ids = {
        assessment.finding_id
        for assessment in db.list_triage_assessments(config=config)
    }
    findings = {
        finding.id: finding
        for finding in db.list_findings(config=config)
        if finding.id is not None
    }
    human_labels_by_rule = Counter(label.rule_id for label in labels)
    candidates_by_engagement: dict[str, dict[str, list[ReviewAcquisitionCandidate]]] = (
        defaultdict(lambda: defaultdict(list))
    )
    available = eligible = 0
    for feature in db.list_triage_features(config):
        finding = findings.get(feature.finding_id)
        if (
            finding is None
            or feature.finding_id in assessed_ids
            or (feature.engagement, feature.fingerprint) in labelled_keys
        ):
            continue
        available += 1
        if human_labels_by_rule[feature.rule_id] > max_prior_human_labels_per_rule:
            continue
        eligible += 1
        selection_hash = _digest(
            "candidate",
            feature.engagement,
            feature.fingerprint,
        )
        candidates_by_engagement[feature.engagement][feature.rule_id].append(
            ReviewAcquisitionCandidate(
                finding_id=feature.finding_id,
                engagement=feature.engagement,
                rule_id=feature.rule_id,
                fingerprint=feature.fingerprint,
                title=finding.title,
                file=finding.file,
                line=finding.line_start,
                prior_human_labels_for_rule=human_labels_by_rule[feature.rule_id],
                selection_hash=selection_hash,
            )
        )

    queues: dict[str, list[ReviewAcquisitionCandidate]] = {}
    for engagement, by_rule in candidates_by_engagement.items():
        for rule_candidates in by_rule.values():
            rule_candidates.sort(key=lambda item: item.selection_hash)
        ordered_rules = sorted(
            by_rule,
            key=lambda rule: (
                human_labels_by_rule[rule],
                _digest("rule", engagement, rule),
            ),
        )
        # Take one candidate from every rule before a second from any rule.
        queue: list[ReviewAcquisitionCandidate] = []
        depth = 0
        while len(queue) < sum(len(items) for items in by_rule.values()):
            for rule in ordered_rules:
                if depth < len(by_rule[rule]):
                    queue.append(by_rule[rule][depth])
            depth += 1
        queues[engagement] = queue

    selected: list[ReviewAcquisitionCandidate] = []
    engagement_counts: Counter[str] = Counter()
    engagements = sorted(queues, key=lambda name: _digest("engagement", name))
    depth = 0
    while len(selected) < limit:
        added = False
        for engagement in engagements:
            if engagement_counts[engagement] >= max_per_engagement:
                continue
            queue = queues[engagement]
            if depth >= len(queue):
                continue
            selected.append(queue[depth])
            engagement_counts[engagement] += 1
            added = True
            if len(selected) >= limit:
                break
        if not added:
            break
        depth += 1

    return ReviewAcquisitionPlan(
        schema_version="triage-review-acquisition-v1",
        selection_policy=(
            "Round-robin across engagements; within each engagement, least-reviewed rule "
            "families first with stable SHA-256 tie-breaking, taking one candidate per rule "
            "before repeats. Rules above the disclosed prior-human-label cap are excluded. "
            "Candidate scores, predicted classes, severity, verdicts, and code outcomes "
            "are excluded."
        ),
        evaluation_eligible=False,
        requested_limit=limit,
        max_per_engagement=max_per_engagement,
        max_prior_human_labels_per_rule=max_prior_human_labels_per_rule,
        existing_human_labels=len(labels),
        available_unassessed=available,
        eligible_after_rule_cap=eligible,
        entries=tuple(selected),
        limitations=(
            "Training acquisition only; adaptive rule-coverage selection is not an evaluation holdout.",
            "Rule identifiers diversify scanner families but do not establish vulnerability mechanisms.",
            "Coverage dimensions must be declared by the analyst after reviewing code evidence.",
            "Uncertain cases must remain explicit abstentions.",
        ),
    )


def render_review_acquisition_plan(plan: ReviewAcquisitionPlan) -> str:
    """Return stable, human-readable JSON suitable for freezing before review."""
    return json.dumps(asdict(plan), indent=2, sort_keys=True) + "\n"


def load_review_acquisition_plan(path: Path) -> ReviewAcquisitionPlan:
    """Load one frozen acquisition plan, rejecting incompatible schemas."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("schema_version") != "triage-review-acquisition-v1":
        raise ValueError("unsupported triage review acquisition schema")
    try:
        entries = tuple(
            ReviewAcquisitionCandidate(**entry) for entry in payload.pop("entries")
        )
        payload["limitations"] = tuple(payload["limitations"])
        return ReviewAcquisitionPlan(entries=entries, **payload)
    except (KeyError, TypeError) as exc:
        raise ValueError("invalid triage review acquisition plan") from exc


def render_review_packet(
    plan: ReviewAcquisitionPlan,
    config: Config | None = None,
    *,
    context_lines: int = 8,
) -> str:
    """Render bounded source evidence without proposing analyst dispositions."""
    if context_lines < 0:
        raise ValueError("context_lines cannot be negative")
    config = config or get_config()
    findings = {
        finding.id: finding
        for finding in db.list_findings(config=config)
        if finding.id is not None
    }
    features = {
        feature.finding_id: feature
        for feature in db.list_triage_features(config)
    }
    snapshots: dict[str, list] = defaultdict(list)
    for repo in db.list_ingested_repos(config, all_snapshots=True):
        snapshots[repo.repo_id].append(repo)
    lines = [
        "# Triage review packet",
        "",
        f"Schema: `{plan.schema_version}`",
        f"Candidates: {len(plan.entries)}",
        "",
        "This packet supplies bounded source evidence only. It does not recommend a",
        "disposition, infer a coverage dimension, or make this training tranche eligible",
        "for evaluation. Review the surrounding repository evidence before deciding.",
        "",
    ]
    for index, candidate in enumerate(plan.entries, start=1):
        finding = findings.get(candidate.finding_id)
        feature = features.get(candidate.finding_id)
        if (
            finding is None
            or feature is None
            or finding.repo_id != candidate.engagement
            or finding.file != candidate.file
            or finding.line_start != candidate.line
            or feature.engagement != candidate.engagement
            or feature.rule_id != candidate.rule_id
            or feature.fingerprint != candidate.fingerprint
        ):
            raise ValueError(
                f"frozen candidate #{candidate.finding_id} differs from stored evidence"
            )
        repo_snapshots = snapshots.get(candidate.engagement, [])
        if len(repo_snapshots) != 1:
            raise ValueError(
                f"engagement {candidate.engagement} resolves to "
                f"{len(repo_snapshots)} snapshots; exact snapshot required"
            )
        repo = repo_snapshots[0]
        root = config.paths.data_dir / "raw" / repo.repo_id / repo.commit_hash
        source = (root / candidate.file).resolve()
        if not source.is_relative_to(root.resolve()) or not source.is_file():
            raise ValueError(
                f"frozen source is unavailable for finding #{candidate.finding_id}"
            )
        source_lines = source.read_text(errors="replace").splitlines()
        if candidate.line < 1 or candidate.line > len(source_lines):
            raise ValueError(
                f"frozen line is unavailable for finding #{candidate.finding_id}"
            )
        start = max(1, candidate.line - context_lines)
        end = min(len(source_lines), candidate.line + context_lines)
        width = len(str(end))
        excerpt = "\n".join(
            f"{line_no:>{width}}  {source_lines[line_no - 1]}"
            for line_no in range(start, end + 1)
        )
        lines.extend([
            f"## {index}. Finding #{candidate.finding_id}",
            "",
            f"- Engagement: `{candidate.engagement}`",
            f"- Snapshot: `{repo.commit_hash}`",
            f"- Rule: `{candidate.rule_id}`",
            f"- Prior human labels for rule: {candidate.prior_human_labels_for_rule}",
            f"- Source: `{candidate.file}:{candidate.line}`",
            "",
            "````text",
            excerpt,
            "````",
            "",
            "Record the reviewed result with:",
            "",
            "```sh",
            f"uv run repoauditor triage-label {candidate.finding_id} \\",
            "  --disposition <detailed-disposition> \\",
            '  --rationale "<evidence-based rationale>"',
            "```",
            "",
            "Add repeatable `--dimension` values only after verifying them from evidence.",
            "",
        ])
    return "\n".join(lines)


def _digest(kind: str, *values: str) -> str:
    material = "\0".join(("triage-review-acquisition-v1", kind, *values))
    return hashlib.sha256(material.encode()).hexdigest()
