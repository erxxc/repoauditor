"""Ground-truth `TriageLabel` generation: derived (closed loop) + manual (analyst override).

The triage classifier learns P(actionable) from labelled findings. This module is where
those labels come from — two sources, with manual taking precedence over derived:

Derived labels (the closed loop)
--------------------------------
Decisions are already logged elsewhere in the pipeline; this harvests them into labels
instead of asking an analyst to re-enter what the pipeline already concluded. For every
deterministic-tool finding that has a persisted feature row (i.e. was actually triaged),
a disposition is derived from:

  1. The human **review decision**, if one exists (`review/`): CONFIRM -> actionable,
     DISMISS -> not actionable. This overrides the falsify verdict because a human
     ruling is stronger ground truth than the automated pass.
  2. Otherwise the **falsify verdict** (`falsify/`): CONFIRMED -> actionable, KILLED ->
     not actionable. UNRESOLVED / DEFERRED yield *no* label — "genuinely ambiguous" and
     "not yet examined" are not evidence either way, and fabricating a label from them
     would poison the training set. Nothing is invented; a finding with no verdict and no
     review decision simply produces no derived label.

Mapping rationale — "does falsify-CONFIRMED always imply true-positive, or only if it also
survived review?" A CONFIRMED verdict *is* the pipeline's designated disprove-it gate
(reachability / mitigating control / attacker-controlled input); surviving it is precisely
what "a real, worth-fixing issue" means here, so CONFIRMED alone is a valid positive label.
Requiring "also survived review" would exclude almost every finding, because `review/` only
holds *unresolved* findings — a CONFIRMED finding normally never reaches review at all. So
the layering is: falsify gives the base label; a human review decision, when present,
overrides it. That handles the "survived review" concern without gutting the label yield.

Manual labels (analyst override)
--------------------------------
`repoauditor triage-label <finding-id> --disposition=...` lets an analyst assert a label
directly. It is written with source MANUAL and, via the `protect_manual` guard in
`db.upsert_triage_label`, can never be overwritten by a later derivation pass — the manual
call is the final word for that finding (an analyst can still correct their own manual call).

This module never touches SQLite directly — only `store/db.py`.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..config import Config, get_config
from ..store import db
from ..store.models import (
    FalsificationStatus,
    ReviewDisposition,
    TriageAssessment,
    TriageAssessmentOutcome,
    TriageDisposition,
    TriageLabel,
    TriageLabelSource,
)


@dataclass
class DerivedLabelSummary:
    """What one derivation pass wrote — for the CLI/caller to report (never silent)."""

    written: int          # labels inserted/updated this pass (manual rows are skipped)
    from_falsify: int     # derived from a falsify verdict
    from_review: int      # derived from a human review decision (overrode any verdict)
    skipped_ambiguous: int  # findings with no verdict/decision -> deliberately no label


def _derive_disposition(
    falsification_status: FalsificationStatus,
    review: ReviewDisposition | None,
) -> tuple[bool, TriageLabelSource] | None:
    """Map a finding's downstream outcomes to (actionable, source), or None for no label.

    Human review overrides the automated falsify verdict; UNRESOLVED/DEFERRED and an
    absent review decision produce no label (not enough signal to assert either way).
    """
    if review is ReviewDisposition.CONFIRM:
        return True, TriageLabelSource.DERIVED_REVIEW
    if review is ReviewDisposition.DISMISS:
        return False, TriageLabelSource.DERIVED_REVIEW
    if falsification_status == FalsificationStatus.CONFIRMED:
        return True, TriageLabelSource.DERIVED_FALSIFY
    if falsification_status == FalsificationStatus.KILLED:
        return False, TriageLabelSource.DERIVED_FALSIFY
    return None


def derive_labels(config: Config | None = None) -> DerivedLabelSummary:
    """Harvest falsify verdicts + review decisions across all engagements into TriageLabels.

    Idempotent and re-runnable: each pass refreshes derived rows from the latest pipeline
    state, and the `protect_manual` guard means manual labels are never disturbed. Scoped
    to findings that carry a `triage_features` row, which is exactly the deterministic-tool
    findings triage is responsible for (LLM-lens findings have no such row and are skipped).
    """
    config = config or get_config()
    feature_rows = {r.finding_id: r for r in db.list_triage_features(config)}
    if not feature_rows:
        return DerivedLabelSummary(0, 0, 0, 0)

    review_by_repo: dict[str, dict[int, ReviewDisposition]] = {}
    summary = DerivedLabelSummary(0, 0, 0, 0)
    for finding in db.list_findings(None, config):
        record = feature_rows.get(finding.id)
        if record is None:
            continue  # not a triaged deterministic-tool finding
        if finding.repo_id not in review_by_repo:
            review_by_repo[finding.repo_id] = db.review_dispositions(finding.repo_id, config)
        review = review_by_repo[finding.repo_id].get(finding.id)
        derived = _derive_disposition(finding.falsification_status, review)
        if derived is None:
            summary.skipped_ambiguous += 1
            continue
        actionable, source = derived
        note = (
            f"derived from {'review ' + review.value if source is TriageLabelSource.DERIVED_REVIEW else 'falsify ' + finding.falsification_status.value}"
        )
        db.upsert_triage_label(
            TriageLabel(
                engagement=record.engagement,
                rule_id=record.rule_id,
                finding_fingerprint=record.fingerprint,
                actionable=actionable,
                source=source,
                note=note,
            ),
            config,
            protect_manual=True,
        )
        summary.written += 1
        if source is TriageLabelSource.DERIVED_REVIEW:
            summary.from_review += 1
        else:
            summary.from_falsify += 1
    return summary


def label_finding(
    finding_id: int,
    actionable: bool,
    note: str | None = None,
    config: Config | None = None,
) -> TriageLabel:
    """Record a MANUAL analyst label on a finding (overrides any derived label).

    Resolves the finding's rule + fingerprint from its persisted `triage_features` row, so
    the manual label keys the same way a derived one does and joins to the same feature
    vector for training. Raises `ValueError` (surfaced cleanly by the thin CLI) if the
    finding doesn't exist or hasn't been triaged yet — a manual label with no features to
    learn from would be a dead-end, so we point the analyst at running triage first.
    """
    config = config or get_config()
    finding = db.get_finding(finding_id, config)
    if finding is None:
        raise ValueError(f"no finding with id {finding_id}")
    record = db.get_triage_features(finding_id, config)
    if record is None:
        raise ValueError(
            f"finding {finding_id} has no triage features yet — run "
            f"`repoauditor triage {finding.repo_id}` first so it is triaged and labellable"
        )
    label = TriageLabel(
        engagement=record.engagement,
        rule_id=record.rule_id,
        finding_fingerprint=record.fingerprint,
        actionable=actionable,
        source=TriageLabelSource.MANUAL,
        note=note,
    )
    db.upsert_triage_label(label, config)  # no protect guard: an analyst is authoritative
    return label


def assess_finding(
    finding_id: int,
    outcome: TriageAssessmentOutcome | TriageDisposition,
    rationale: str,
    analyst: str,
    dimensions: list[str] | None = None,
    config: Config | None = None,
    *,
    material: bool = False,
) -> tuple[TriageAssessment, TriageLabel | None]:
    """Record an auditable analyst assessment and optionally produce a binary label.

    The detailed disposition is retained while its deterministic projection preserves the
    classifier's binary contract. `INSUFFICIENT_EVIDENCE`/legacy `UNCERTAIN` is a first-class
    abstention and never enters training.
    """
    config = config or get_config()
    rationale = rationale.strip()
    analyst = analyst.strip()
    if not rationale:
        raise ValueError("an analyst rationale is required")
    if not analyst:
        raise ValueError("an analyst identity is required")
    finding = db.get_finding(finding_id, config)
    if finding is None:
        raise ValueError(f"no finding with id {finding_id}")
    record = db.get_triage_features(finding_id, config)
    engagement = record.engagement if record is not None else finding.repo_id
    if isinstance(outcome, TriageAssessmentOutcome):
        disposition = {
            TriageAssessmentOutcome.TRUE_POSITIVE:
                TriageDisposition.CONFIRMED_ACTIONABLE,
            TriageAssessmentOutcome.FALSE_POSITIVE:
                TriageDisposition.TOOL_INCORRECT,
            TriageAssessmentOutcome.UNCERTAIN:
                TriageDisposition.INSUFFICIENT_EVIDENCE,
        }[outcome]
    else:
        disposition = outcome
        outcome = disposition.outcome
    clean_dimensions = sorted({item.strip() for item in dimensions or [] if item.strip()})
    assessment = TriageAssessment(
        finding_id=finding_id, engagement=engagement, outcome=outcome,
        disposition=disposition, rationale=rationale, analyst=analyst,
        material=material, classifier_eligible=record is not None,
        dimensions=clean_dimensions,
    )
    assessment_id = db.insert_triage_assessment(assessment, config)
    assessment = assessment.model_copy(update={"id": assessment_id})
    if outcome is TriageAssessmentOutcome.UNCERTAIN:
        return assessment, None
    if material:
        latest_by_analyst = {
            item.analyst: item
            for item in db.list_triage_assessments(engagement, config)
            if item.finding_id == finding_id and item.material
        }
        independently_confirmed = any(
            item.analyst != analyst
            and item.outcome is outcome
            and item.disposition is disposition
            for item in latest_by_analyst.values()
        )
        if not independently_confirmed:
            if record is not None:
                db.delete_triage_label_projection(
                    record.engagement, record.fingerprint, config
                )
            return assessment, None
    if record is None:
        return assessment, None
    label = label_finding(
        finding_id,
        actionable=outcome is TriageAssessmentOutcome.TRUE_POSITIVE,
        note=rationale,
        config=config,
    )
    return assessment, label
