"""Evaluation-only solution-refinement checks for falsification.

Computational V&V distinguishes verification (did the implementation execute its stated
method?) from validation (does the method represent reality?). This module addresses a
narrow verification question: does a falsification result remain stable when the resolution
of the instrument changes while the repository snapshot, finding, prompts, model, and
decision thresholds remain fixed?

The experiment never persists a verdict or changes pipeline behavior. It disables artifact
persistence while challenging the same finding identity at coarse, standard, and refined
retrieval/iteration profiles. Non-convergence is reported, not automatically converted into
a kill/confirm decision.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path

from pydantic import BaseModel, Field

from ..config import Config, get_config
from ..detect.retrieval import RetrievalIndex
from ..falsify import FalsificationResolution, challenge_finding
from ..falsify.claims import claim_from_slice, verify_structural_claim
from ..falsify.slicing import build_python_slice
from ..ingest import latest_snapshot
from ..llm import LLMClient, get_llm_client
from ..map import ArchitectureMap, load_architecture
from ..store import db
from ..store.models import FalsificationStatus, Finding
from .regression import STAGE_PROMPT_VERSIONS

_CITATION_RE = re.compile(r"^# [^:\n]+: .* \(([^()]+:\d+-\d+)\)$", re.MULTILINE)


class ResolutionProfile(BaseModel):
    """One ordered instrument resolution; profiles must progress coarse-to-refined."""

    name: str
    max_iterations: int = Field(ge=1)
    local_context_lines: int = Field(ge=0)
    related_result_base: int = Field(ge=0)
    module_context_lines: int = Field(ge=0)
    max_evidence_chars: int = Field(ge=1)

    def challenger_resolution(self) -> FalsificationResolution:
        return FalsificationResolution(
            name=self.name,
            local_context_lines=self.local_context_lines,
            related_result_base=self.related_result_base,
            module_context_lines=self.module_context_lines,
            max_evidence_chars=self.max_evidence_chars,
        )


DEFAULT_PROFILES: tuple[ResolutionProfile, ...] = (
    ResolutionProfile(
        name="coarse",
        max_iterations=1,
        local_context_lines=6,
        related_result_base=1,
        module_context_lines=12,
        max_evidence_chars=6_000,
    ),
    ResolutionProfile(
        name="standard",
        max_iterations=2,
        local_context_lines=10,
        related_result_base=2,
        module_context_lines=18,
        max_evidence_chars=12_000,
    ),
    ResolutionProfile(
        name="refined",
        max_iterations=3,
        local_context_lines=18,
        related_result_base=5,
        module_context_lines=30,
        max_evidence_chars=24_000,
    ),
)


class ConvergenceObservation(BaseModel):
    resolution: str
    max_iterations: int
    verdict: FalsificationStatus
    confidence: float
    evidence_citations: list[str] = Field(default_factory=list)
    evidence_characters: int
    structural_claim_status: str


class ConvergenceResult(BaseModel):
    """One non-mutating refinement experiment and its descriptive stability metrics."""

    repo_id: str
    finding_id: int
    snapshot_commit: str
    model: str
    provider: str
    prompt_versions: dict[str, str]
    sampling_seed: int | None
    observations: list[ConvergenceObservation]
    classification: str
    verdict_flip_rate: float
    adjacent_evidence_jaccard: float | None
    confidence_spread: float
    first_stable_resolution: str | None


def _citations(evidence_blocks: Sequence[str]) -> list[str]:
    return sorted({
        citation
        for block in evidence_blocks
        for citation in _CITATION_RE.findall(block)
    })


def _jaccard(left: set[str], right: set[str]) -> float | None:
    union = left | right
    return len(left & right) / len(union) if union else None


def _classification(verdicts: list[FalsificationStatus]) -> str:
    if all(verdict is FalsificationStatus.UNRESOLVED for verdict in verdicts):
        return "unresolved"
    if len(set(verdicts)) == 1:
        return "stable"
    if len(verdicts) >= 3 and verdicts[0] == verdicts[-1]:
        return "oscillating"
    return "non_convergent"


def _first_stable(
    observations: list[ConvergenceObservation],
) -> str | None:
    # Require at least two matching suffix observations: the final point alone is not
    # evidence of convergence.
    for index in range(len(observations) - 1):
        suffix = observations[index:]
        if len({item.verdict for item in suffix}) == 1:
            return observations[index].resolution
    return None


def _validate_profiles(profiles: Sequence[ResolutionProfile]) -> None:
    if len(profiles) < 2:
        raise ValueError("convergence evaluation requires at least two resolutions")
    if len({profile.name for profile in profiles}) != len(profiles):
        raise ValueError("convergence resolution names must be unique")
    dimensions = (
        "max_iterations",
        "local_context_lines",
        "related_result_base",
        "module_context_lines",
        "max_evidence_chars",
    )
    for coarse, refined in zip(profiles, profiles[1:]):
        before = tuple(getattr(coarse, name) for name in dimensions)
        after = tuple(getattr(refined, name) for name in dimensions)
        if any(right < left for left, right in zip(before, after)):
            raise ValueError(
                f"resolution {refined.name!r} is coarser than {coarse.name!r}"
            )
        if after == before:
            raise ValueError(
                f"resolution {refined.name!r} does not refine {coarse.name!r}"
            )


def _metrics(
    *,
    repo_id: str,
    finding_id: int,
    commit: str,
    config: Config,
    llm: LLMClient,
    observations: list[ConvergenceObservation],
) -> ConvergenceResult:
    verdicts = [item.verdict for item in observations]
    flips = sum(left != right for left, right in zip(verdicts, verdicts[1:]))
    comparisons = max(len(verdicts) - 1, 1)
    overlaps = [
        overlap
        for left, right in zip(observations, observations[1:])
        if (
            overlap := _jaccard(
                set(left.evidence_citations), set(right.evidence_citations)
            )
        ) is not None
    ]
    confidences = [item.confidence for item in observations]
    return ConvergenceResult(
        repo_id=repo_id,
        finding_id=finding_id,
        snapshot_commit=commit,
        model=config.model.name,
        provider=config.llm.provider,
        prompt_versions={"falsify": STAGE_PROMPT_VERSIONS["falsify"]},
        sampling_seed=llm.sampling_seed,
        observations=observations,
        classification=_classification(verdicts),
        verdict_flip_rate=flips / comparisons,
        adjacent_evidence_jaccard=(
            sum(overlaps) / len(overlaps) if overlaps else None
        ),
        confidence_spread=max(confidences) - min(confidences),
        first_stable_resolution=_first_stable(observations),
    )


def run_finding_convergence(
    finding: Finding,
    *,
    snapshot_path: Path,
    snapshot_commit: str,
    architecture: ArchitectureMap,
    index: RetrievalIndex,
    llm: LLMClient,
    config: Config,
    profiles: Sequence[ResolutionProfile] = DEFAULT_PROFILES,
) -> ConvergenceResult:
    """Run ordered resolution profiles without persisting evaluation artifacts."""
    if finding.id is None:
        raise ValueError("convergence evaluation requires a persisted finding id")
    _validate_profiles(profiles)

    original_id = finding.id
    slice_evidence = build_python_slice(index, finding)
    if slice_evidence is None:
        structural_status = "absent_or_unsupported"
    else:
        claim = claim_from_slice(original_id, slice_evidence, snapshot_commit)
        structural_status = verify_structural_claim(
            claim, snapshot_path, snapshot_commit
        ).status.value

    observations: list[ConvergenceObservation] = []
    for profile in profiles:
        evidence_blocks: list[str] = []
        eval_config = config.model_copy(update={
            "falsify": config.falsify.model_copy(
                update={"max_iterations": profile.max_iterations}
            )
        })
        outcome = challenge_finding(
            finding,
            architecture,
            llm,
            index=index,
            config=eval_config,
            self_critique=True,
            snapshot_commit=snapshot_commit,
            resolution=profile.challenger_resolution(),
            evidence_observer=lambda _iteration, block: evidence_blocks.append(block),
            minimum_iterations=profile.max_iterations,
            persist_artifacts=False,
        )
        observations.append(ConvergenceObservation(
            resolution=profile.name,
            max_iterations=profile.max_iterations,
            verdict=outcome.status,
            confidence=outcome.confidence,
            evidence_citations=_citations(evidence_blocks),
            evidence_characters=sum(len(block) for block in evidence_blocks),
            structural_claim_status=structural_status,
        ))

    return _metrics(
        repo_id=finding.repo_id,
        finding_id=original_id,
        commit=snapshot_commit,
        config=config,
        llm=llm,
        observations=observations,
    )


def evaluate_finding_convergence(
    finding_id: int,
    config: Config | None = None,
    llm: LLMClient | None = None,
) -> ConvergenceResult:
    """Resolve stored inputs and run a non-mutating convergence experiment."""
    config = config or get_config()
    finding = db.get_finding(finding_id, config)
    if finding is None:
        raise ValueError(f"finding #{finding_id} does not exist")
    snapshot_path, commit = latest_snapshot(config, finding.repo_id)
    architecture = load_architecture(finding.repo_id, commit, config)
    index = RetrievalIndex().build(snapshot_path)
    return run_finding_convergence(
        finding,
        snapshot_path=snapshot_path,
        snapshot_commit=commit,
        architecture=architecture,
        index=index,
        llm=llm or get_llm_client(config),
        config=config,
    )


def render_convergence(result: ConvergenceResult) -> str:
    """Human-readable evaluation output; no threshold recommendation."""
    rows = [
        (
            f"{item.resolution:<9} iterations={item.max_iterations} "
            f"verdict={item.verdict.value:<10} confidence={item.confidence:.3f} "
            f"citations={len(item.evidence_citations)} "
            f"evidence_chars={item.evidence_characters}"
        )
        for item in result.observations
    ]
    seed = (
        str(result.sampling_seed)
        if result.sampling_seed is not None
        else "unavailable (provider calls are not seed-reproducible)"
    )
    overlap = (
        f"{result.adjacent_evidence_jaccard:.3f}"
        if result.adjacent_evidence_jaccard is not None
        else "unavailable (no extracted evidence citations)"
    )
    stable_at = result.first_stable_resolution or "not observed"
    return "\n".join([
        (
            f"Falsification convergence — finding #{result.finding_id}, "
            f"repo {result.repo_id}, commit {result.snapshot_commit}"
        ),
        *rows,
        (
            f"result={result.classification}; flip_rate={result.verdict_flip_rate:.3f}; "
            f"evidence_jaccard={overlap}; confidence_spread={result.confidence_spread:.3f}; "
            f"stable_from={stable_at}"
        ),
        (
            f"instrument={result.provider}/{result.model}; sampling_seed={seed}; "
            "evaluation only — no finding or verdict was changed"
        ),
    ])
