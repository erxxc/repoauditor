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
from .acquisition_funnel import (
    AcquisitionFunnelCounts,
    AcquisitionIdentityInput,
    ReviewPathClass,
    ReviewPathTier,
    classify_review_path,
    exact_location_identity,
    pre_post_identity,
    repeated_family_identity,
    review_path_tier,
)


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
    surface: str = "production"
    producer: str = "unknown"
    path_class: str = "production"
    path_tier: str = "tier_1_product_deployment"
    family_hash: str = ""
    line_end: int = 0
    identity_hash: str = ""


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
    max_per_family_per_engagement: int = 2
    included_path_tiers: tuple[str, ...] = (
        "tier_1_product_deployment",
        "tier_2_supporting",
    )
    declared_pre_post_pairs: tuple[tuple[str, str], ...] = ()
    input_digest: str = ""
    funnel: AcquisitionFunnelCounts | None = None
    deferred_by_stage: dict[str, int] | None = None
    path_class_counts: dict[str, int] | None = None
    family_counts_before_cap: dict[str, int] | None = None


def build_review_acquisition_plan(
    config: Config | None = None,
    *,
    limit: int = 32,
    max_per_engagement: int = 4,
    max_prior_human_labels_per_rule: int = 5,
    max_per_family_per_engagement: int = 2,
    include_vendor_generated: bool = False,
    pre_post_pairs: tuple[tuple[str, str], ...] = (),
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
    if max_per_family_per_engagement <= 0:
        raise ValueError("max_per_family_per_engagement must be positive")
    _validate_pre_post_pairs(pre_post_pairs)
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
    eligible_candidates: list[ReviewAcquisitionCandidate] = []
    identity_inputs: dict[int, AcquisitionIdentityInput] = {}
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
        producer = finding.source_tool or finding.source_lens or "unknown"
        path_class = classify_review_path(finding.file)
        path_tier = review_path_tier(path_class)
        identity = AcquisitionIdentityInput(
            engagement=feature.engagement,
            producer=producer,
            rule_id=feature.rule_id,
            file=finding.file,
            line_start=finding.line_start,
            line_end=finding.line_end,
            sink=finding.citation_snippet,
        )
        candidate = ReviewAcquisitionCandidate(
            finding_id=feature.finding_id,
            engagement=feature.engagement,
            rule_id=feature.rule_id,
            fingerprint=feature.fingerprint,
            title=finding.title,
            file=finding.file,
            line=finding.line_start,
            prior_human_labels_for_rule=human_labels_by_rule[feature.rule_id],
            selection_hash=selection_hash,
            surface=_review_surface(finding.file),
            producer=producer,
            path_class=path_class.value,
            path_tier=path_tier.value,
            family_hash=_digest("family", *repeated_family_identity(identity)),
            line_end=finding.line_end,
            identity_hash=_digest("exact", *exact_location_identity(identity)),
        )
        eligible_candidates.append(candidate)
        identity_inputs[feature.finding_id] = identity

    raw_count = len(eligible_candidates)
    input_digest = _digest(
        "opt-029-input-v1",
        *(
            repr(exact_location_identity(identity_inputs[item.finding_id]))
            for item in sorted(
                eligible_candidates,
                key=lambda candidate: exact_location_identity(
                    identity_inputs[candidate.finding_id]
                ),
            )
        ),
    )
    after_pre_post = _collapse_declared_pre_post(
        eligible_candidates,
        identity_inputs,
        pre_post_pairs,
    )
    after_exact = _stable_unique(
        after_pre_post,
        lambda candidate: exact_location_identity(
            identity_inputs[candidate.finding_id]
        ),
    )
    included_tiers = {
        ReviewPathTier.PRIMARY.value,
        ReviewPathTier.SUPPORTING.value,
    }
    if include_vendor_generated:
        included_tiers.add(ReviewPathTier.DEFERRED.value)
    after_path = [
        candidate
        for candidate in after_exact
        if candidate.path_tier in included_tiers
    ]
    path_class_counts = dict(sorted(Counter(
        candidate.path_class for candidate in after_exact
    ).items()))
    family_groups: dict[
        tuple[str, ...], list[ReviewAcquisitionCandidate]
    ] = defaultdict(list)
    for candidate in after_path:
        family_groups[
            repeated_family_identity(identity_inputs[candidate.finding_id])
        ].append(candidate)
    family_counts = {
        _digest("family", *family_identity): len(candidates)
        for family_identity, candidates in sorted(family_groups.items())
    }
    after_family: list[ReviewAcquisitionCandidate] = []
    for candidates in family_groups.values():
        candidates.sort(key=_candidate_order_key)
        after_family.extend(candidates[:max_per_family_per_engagement])

    candidates_by_engagement: dict[
        str, dict[str, dict[str, list[ReviewAcquisitionCandidate]]]
    ] = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
    for candidate in after_family:
        candidates_by_engagement[candidate.engagement][candidate.rule_id][
            candidate.family_hash
        ].append(candidate)

    queues: dict[str, list[ReviewAcquisitionCandidate]] = {}
    for engagement, by_rule in candidates_by_engagement.items():
        for by_family in by_rule.values():
            for family_candidates in by_family.values():
                family_candidates.sort(key=_candidate_order_key)
        ordered_rules = sorted(
            by_rule,
            key=lambda rule: (
                min(
                    _candidate_path_rank(item)
                    for family in by_rule[rule].values()
                    for item in family
                ),
                human_labels_by_rule[rule],
                _digest("rule", engagement, rule),
            ),
        )
        ordered_families = {
            rule: sorted(
                by_rule[rule],
                key=lambda family_hash: (
                    min(
                        _candidate_path_rank(item)
                        for item in by_rule[rule][family_hash]
                    ),
                    family_hash,
                ),
            )
            for rule in ordered_rules
        }
        # Round-robin rules while building the family order, then take one candidate
        # from every family before a second from any family.
        family_order: list[tuple[str, str]] = []
        family_depth = 0
        family_total = sum(len(families) for families in ordered_families.values())
        while len(family_order) < family_total:
            for rule in ordered_rules:
                if family_depth < len(ordered_families[rule]):
                    family_order.append(
                        (rule, ordered_families[rule][family_depth])
                    )
            family_depth += 1
        queue: list[ReviewAcquisitionCandidate] = []
        depth = 0
        candidate_total = sum(
            len(items)
            for families in by_rule.values()
            for items in families.values()
        )
        while len(queue) < candidate_total:
            for rule, family_hash in family_order:
                family = by_rule[rule][family_hash]
                if depth < len(family):
                    queue.append(family[depth])
            depth += 1
        queues[engagement] = queue

    balanced_count = sum(
        min(len(queue), max_per_engagement) for queue in queues.values()
    )
    selected: list[ReviewAcquisitionCandidate] = []
    engagement_counts: Counter[str] = Counter()
    while len(selected) < limit:
        available_options = [
            (engagement, queue[0])
            for engagement, queue in queues.items()
            if queue and engagement_counts[engagement] < max_per_engagement
        ]
        if not available_options:
            break
        engagement, candidate = min(
            available_options,
            key=lambda item: (
                *_candidate_path_rank(item[1]),
                engagement_counts[item[0]],
                _digest("engagement", item[0]),
                item[1].selection_hash,
            ),
        )
        selected.append(candidate)
        engagement_counts[engagement] += 1
        queues[engagement].pop(0)

    funnel = AcquisitionFunnelCounts(
        raw=raw_count,
        after_pre_post_collapse=len(after_pre_post),
        after_exact_duplicate_collapse=len(after_exact),
        after_path_policy=len(after_path),
        after_family_cap=len(after_family),
        after_engagement_balance=balanced_count,
        selected=len(selected),
    )
    return ReviewAcquisitionPlan(
        schema_version="triage-review-acquisition-v3",
        selection_policy=(
            "After the separately disclosed prior-human-label eligibility gate, exact "
            "evidence repeated across declared pre/post pairs and exact same-location "
            "duplicates are collapsed. Product/deployment paths precede supporting paths; "
            "vendor/generated paths are deferred unless explicitly included. A normalized "
            "producer/rule/sink family is capped per engagement, with one candidate per "
            "rule before repeats. Selection then balances engagements with stable SHA-256 "
            "tie-breaking. Candidate scores, predicted classes, severity, verdicts, code "
            "outcomes, and answer keys are excluded."
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
            "Path classes prioritize review effort but do not predict finding validity.",
            "Coverage dimensions must be declared by the analyst after reviewing code evidence.",
            "Uncertain cases must remain explicit abstentions.",
        ),
        max_per_family_per_engagement=max_per_family_per_engagement,
        included_path_tiers=tuple(sorted(included_tiers)),
        declared_pre_post_pairs=pre_post_pairs,
        input_digest=input_digest,
        funnel=funnel,
        deferred_by_stage=funnel.deferred_by_stage(),
        path_class_counts=path_class_counts,
        family_counts_before_cap=family_counts,
    )


def render_review_acquisition_plan(plan: ReviewAcquisitionPlan) -> str:
    """Return stable, human-readable JSON suitable for freezing before review."""
    return json.dumps(asdict(plan), indent=2, sort_keys=True) + "\n"


def load_review_acquisition_plan(path: Path) -> ReviewAcquisitionPlan:
    """Load one frozen acquisition plan, rejecting incompatible schemas."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("schema_version") not in {
        "triage-review-acquisition-v1",
        "triage-review-acquisition-v2",
        "triage-review-acquisition-v3",
    }:
        raise ValueError("unsupported triage review acquisition schema")
    try:
        entries = tuple(
            ReviewAcquisitionCandidate(**entry) for entry in payload.pop("entries")
        )
        payload["limitations"] = tuple(payload["limitations"])
        if "included_path_tiers" in payload:
            payload["included_path_tiers"] = tuple(payload["included_path_tiers"])
        if "declared_pre_post_pairs" in payload:
            payload["declared_pre_post_pairs"] = tuple(
                tuple(pair) for pair in payload["declared_pre_post_pairs"]
            )
        if payload.get("funnel") is not None:
            payload["funnel"] = AcquisitionFunnelCounts(**payload["funnel"])
        return ReviewAcquisitionPlan(entries=entries, **payload)
    except (KeyError, TypeError) as exc:
        raise ValueError("invalid triage review acquisition plan") from exc


def _review_surface(file: str) -> str:
    normalized = file.replace("\\", "/").lower()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    parts = normalized.split("/")
    name = parts[-1]
    if (
        normalized.startswith(".github/")
        or any(part in {"doc", "docs", "example", "examples", "test", "tests", "spec"}
               for part in parts[:-1])
        or any(part.endswith("-test") or part.endswith("_test") for part in parts[:-1])
        or name.startswith(("readme", "changelog"))
    ):
        return "supporting"
    if (
        name in {"dockerfile", "compose.yml", "compose.yaml", "docker-compose.yml",
                 "docker-compose.yaml"}
        or name.endswith((".yml", ".yaml", ".toml", ".ini", ".cfg", ".properties"))
        or name.startswith(".yarnrc")
    ):
        return "deployment"
    return "production"


def _candidate_order_key(
    candidate: ReviewAcquisitionCandidate,
) -> tuple[int, int, str]:
    return (*_candidate_path_rank(candidate), candidate.selection_hash)


def _candidate_path_rank(
    candidate: ReviewAcquisitionCandidate,
) -> tuple[int, int]:
    tier_rank = {
        ReviewPathTier.PRIMARY.value: 0,
        ReviewPathTier.SUPPORTING.value: 1,
        ReviewPathTier.DEFERRED.value: 2,
    }
    path_rank = {
        ReviewPathClass.PRODUCTION.value: 0,
        ReviewPathClass.DEPLOYMENT.value: 1,
        ReviewPathClass.CI.value: 2,
        ReviewPathClass.TEST.value: 3,
        ReviewPathClass.DOCS_EXAMPLES.value: 4,
        ReviewPathClass.VENDOR_GENERATED.value: 5,
    }
    return (
        tier_rank.get(candidate.path_tier, 3),
        path_rank.get(candidate.path_class, 6),
    )


def _stable_unique(
    candidates: list[ReviewAcquisitionCandidate],
    identity,
) -> list[ReviewAcquisitionCandidate]:
    grouped: dict[tuple[object, ...], list[ReviewAcquisitionCandidate]] = defaultdict(
        list
    )
    for candidate in candidates:
        grouped[identity(candidate)].append(candidate)
    return [
        min(group, key=_candidate_order_key)
        for _, group in sorted(grouped.items(), key=lambda item: repr(item[0]))
    ]


def _validate_pre_post_pairs(pairs: tuple[tuple[str, str], ...]) -> None:
    engagements: set[str] = set()
    for pair in pairs:
        if len(pair) != 2 or not pair[0] or not pair[1]:
            raise ValueError("pre/post pairs require two non-empty engagement ids")
        if pair[0] == pair[1]:
            raise ValueError("pre/post pair engagements must differ")
        if pair[0] in engagements or pair[1] in engagements:
            raise ValueError("an engagement may occur in only one pre/post pair")
        engagements.update(pair)


def _collapse_declared_pre_post(
    candidates: list[ReviewAcquisitionCandidate],
    identities: dict[int, AcquisitionIdentityInput],
    pairs: tuple[tuple[str, str], ...],
) -> list[ReviewAcquisitionCandidate]:
    retained = list(candidates)
    for pre_engagement, post_engagement in pairs:
        pre_identities = {
            pre_post_identity(identities[candidate.finding_id])
            for candidate in retained
            if candidate.engagement == pre_engagement
        }
        retained = [
            candidate
            for candidate in retained
            if not (
                candidate.engagement == post_engagement
                and pre_post_identity(identities[candidate.finding_id])
                in pre_identities
            )
        ]
    return retained


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
            or (
                candidate.identity_hash
                and candidate.identity_hash != _digest(
                    "exact",
                    *exact_location_identity(AcquisitionIdentityInput(
                        engagement=feature.engagement,
                        producer=finding.source_tool or finding.source_lens or "unknown",
                        rule_id=feature.rule_id,
                        file=finding.file,
                        line_start=finding.line_start,
                        line_end=finding.line_end,
                        sink=finding.citation_snippet,
                    )),
                )
            )
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
            f"- Producer: `{candidate.producer}`",
            f"- Prior human labels for rule: {candidate.prior_human_labels_for_rule}",
            f"- Review surface: `{candidate.surface}`",
            f"- OPT-029 path class: `{candidate.path_class}`",
            f"- OPT-029 path tier: `{candidate.path_tier}`",
            f"- OPT-029 family hash: `{candidate.family_hash}`",
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


def _digest(kind: str, *values: object) -> str:
    material = "\0".join((
        "triage-review-acquisition-v1",
        kind,
        *(str(value) for value in values),
    ))
    return hashlib.sha256(material.encode()).hexdigest()
