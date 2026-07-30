"""Mechanism-specific pre/post qualification for deterministic scanner candidates.

The comparison separates target recovery from unrelated candidate churn.  A signal counts
as the advisory target only when its rule identity, file, source citation, and optional line
range satisfy a target specification frozen before the scanner run.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field, model_validator

from ..detect.ensemble import CandidateFinding


class DifferentialClassification(StrEnum):
    VULNERABLE_ONLY_RECOVERY = "vulnerable_only_recovery"
    STABLE_PRE_POST_MECHANISM_SIGNAL = "stable_pre_post_mechanism_signal"
    PATCHED_ONLY_SIGNAL = "patched_only_signal"
    COMPLETE_MISS = "complete_miss"


class AdvisoryTargetSpec(BaseModel):
    """Frozen identity for one advisory mechanism and scanner rule."""

    file: str
    rule_ids: tuple[str, ...] = Field(min_length=1)
    citation_contains: str | None = None
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def _valid_line_range(self) -> "AdvisoryTargetSpec":
        if (self.line_start is None) != (self.line_end is None):
            raise ValueError("target line_start and line_end must be declared together")
        if (
            self.line_start is not None
            and self.line_end is not None
            and self.line_end < self.line_start
        ):
            raise ValueError("target line_end cannot precede line_start")
        return self


class DifferentialCandidate(BaseModel):
    """Serializable candidate evidence retained by a differential result."""

    producer: str
    source_tool: str
    title: str
    file: str
    line_start: int
    line_end: int
    citation_snippet: str


class AdvisoryDifferentialResult(BaseModel):
    schema_version: str = "scanner-advisory-differential-v1"
    classification: DifferentialClassification
    pre_target_matches: list[DifferentialCandidate]
    post_target_matches: list[DifferentialCandidate]
    pre_candidate_count: int = Field(ge=0)
    post_candidate_count: int = Field(ge=0)
    unrelated_stable_count: int = Field(ge=0)
    unrelated_pre_only_count: int = Field(ge=0)
    unrelated_post_only_count: int = Field(ge=0)
    claim_boundary: str = (
        "Target classification is mechanism-specific. Unrelated candidates remain "
        "unadjudicated and are not false positives, labels, or target recovery."
    )


def _normalized_path(value: str) -> str:
    return value.replace("\\", "/").lstrip("./")


def _matches_target(candidate: CandidateFinding, target: AdvisoryTargetSpec) -> bool:
    if _normalized_path(candidate.file) != _normalized_path(target.file):
        return False
    if candidate.title not in target.rule_ids:
        return False
    if (
        target.citation_contains is not None
        and target.citation_contains not in candidate.citation_snippet
    ):
        return False
    if target.line_start is not None and target.line_end is not None:
        if candidate.line_end < target.line_start or candidate.line_start > target.line_end:
            return False
    return True


def _evidence(candidate: CandidateFinding) -> DifferentialCandidate:
    return DifferentialCandidate(
        producer=candidate.producer or candidate.source_tool,
        source_tool=candidate.source_tool,
        title=candidate.title,
        file=_normalized_path(candidate.file),
        line_start=candidate.line_start,
        line_end=candidate.line_end,
        citation_snippet=candidate.citation_snippet,
    )


def _identity(candidate: CandidateFinding) -> tuple[str, str, str, int, int, str, str]:
    evidence = _evidence(candidate)
    return (
        evidence.producer,
        evidence.source_tool,
        evidence.file,
        evidence.line_start,
        evidence.line_end,
        evidence.title,
        evidence.citation_snippet,
    )


def classify_advisory_pair(
    *,
    pre_candidates: list[CandidateFinding],
    post_candidates: list[CandidateFinding],
    target: AdvisoryTargetSpec,
) -> AdvisoryDifferentialResult:
    """Classify a frozen target and separately account for unrelated candidates."""
    pre_matches = [candidate for candidate in pre_candidates if _matches_target(candidate, target)]
    post_matches = [
        candidate for candidate in post_candidates if _matches_target(candidate, target)
    ]
    if pre_matches and not post_matches:
        classification = DifferentialClassification.VULNERABLE_ONLY_RECOVERY
    elif pre_matches and post_matches:
        classification = DifferentialClassification.STABLE_PRE_POST_MECHANISM_SIGNAL
    elif post_matches:
        classification = DifferentialClassification.PATCHED_ONLY_SIGNAL
    else:
        classification = DifferentialClassification.COMPLETE_MISS

    pre_unrelated = {
        _identity(candidate)
        for candidate in pre_candidates
        if not _matches_target(candidate, target)
    }
    post_unrelated = {
        _identity(candidate)
        for candidate in post_candidates
        if not _matches_target(candidate, target)
    }
    return AdvisoryDifferentialResult(
        classification=classification,
        pre_target_matches=[_evidence(candidate) for candidate in pre_matches],
        post_target_matches=[_evidence(candidate) for candidate in post_matches],
        pre_candidate_count=len(pre_candidates),
        post_candidate_count=len(post_candidates),
        unrelated_stable_count=len(pre_unrelated & post_unrelated),
        unrelated_pre_only_count=len(pre_unrelated - post_unrelated),
        unrelated_post_only_count=len(post_unrelated - pre_unrelated),
    )
