"""Falsification challenger — a bounded observe-think-act-reflect loop.

The challenger's only job is to try to *disprove* a candidate finding: is the
vulnerable code reachable from an entry point, is the flagged input actually
attacker-controlled, and is there a mitigating control elsewhere in the retrieved
context? It returns confirmed / killed / unresolved with a written reason.

Rather than a single shot, each candidate runs a **bounded loop** (max iterations from
`config.falsify.max_iterations`). Each round: gather evidence (reachability + mitigating
controls via `detect/retrieval/`, broadening the search each round), form a verdict,
then a **self-critique** step where the model audits its own verdict against the
evidence it actually gathered before committing. The loop commits only on a confident,
self-critique-upheld confirm/kill; if it exhausts the iteration budget without one it
degrades gracefully to `unresolved` — never forcing a verdict past the limit, never
looping unbounded. Every round (evidence + verdict + critique) is logged so a `review/`
reviewer can follow the reasoning trace.

Killed findings are **not** deleted — the repo-level runner persists every verdict
(and its reason) back to the store, so nothing silently disappears (null-result
logging). A `confirmed` verdict is one of the two things (the other being
cross-source corroboration) that licenses a severity upgrade downstream.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ..config import Config, get_config
from ..ingest import latest_snapshot
from ..llm import LLMClient, get_llm_client, remaining_pipeline_call_capacity
from ..map import ArchitectureMap, load_architecture
from ..store import db
from ..store.models import (
    FalsificationIteration,
    FalsificationStatus,
    Finding,
    TriageResult,
    severity_rank,
)
from ..detect.retrieval import RetrievalIndex
from ..llm.prompt_security import (
    PROMPT_SECURITY_VERSION,
    delimit_repository_evidence,
    secure_system_prompt,
)

# Re-exported: the model's structured output shape for a falsification verdict.
from .outcome import FalsificationOutcome, SelfCritique
from .claims import claim_from_slice, verify_structural_claim
from .slicing import StructuralSliceEvidence, build_structural_slice

_PROMPT_ARTIFACT = "falsification_v2"
PROMPT_VERSION = f"{_PROMPT_ARTIFACT}+{PROMPT_SECURITY_VERSION}"
PROMPT = (Path(__file__).parent / "prompts" / f"{_PROMPT_ARTIFACT}.md").read_text()

_CRITIQUE_PROMPT_ARTIFACT = "falsification_selfcritique_v1"
CRITIQUE_PROMPT_VERSION = f"{_CRITIQUE_PROMPT_ARTIFACT}+{PROMPT_SECURITY_VERSION}"
CRITIQUE_PROMPT = (
    Path(__file__).parent / "prompts" / f"{_CRITIQUE_PROMPT_ARTIFACT}.md"
).read_text()
CONTEXT_VERSION = "falsification_context_v3"

_TERMINAL = (FalsificationStatus.CONFIRMED, FalsificationStatus.KILLED)
_REFERENCE_TOKEN_RE = re.compile(r"\b(?:[A-Z][A-Z0-9_]{3,}|[A-Za-z_]\w*_bp)\b")
_MAX_EVIDENCE_CHARS = 12_000


@dataclass(frozen=True)
class FalsificationResolution:
    """Evaluation seam for perturbing instrument resolution, never the subject.

    Production callers use the defaults, which exactly preserve the normal retrieval
    policy. Convergence experiments may supply a different immutable profile without
    changing repository content, prompts, thresholds, or the persisted finding.
    """

    name: str = "production"
    local_context_lines: int = 10
    related_result_base: int = 2
    module_context_lines: int = 18
    max_evidence_chars: int = _MAX_EVIDENCE_CHARS


def _format_context(label: str, blocks: list) -> str:
    rendered = []
    seen: set[tuple[str, int, int, str]] = set()
    for info in blocks:
        key = (info.file, info.line_start, info.line_end, info.source)
        if key in seen:
            continue
        seen.add(key)
        rendered.append(
            f"# {label}: {info.symbol} ({info.file}:{info.line_start}-{info.line_end})\n"
            f"{info.source}"
        )
    return "\n\n".join(rendered)


def _architecture_context(architecture: ArchitectureMap) -> str:
    if not architecture.entry_points:
        return "# ARCHITECTURE ENTRY POINTS\n(none recovered)"
    rows = [
        f"- {entry.name} | location={entry.location or '(unknown)'} | "
        f"trust_boundary={entry.trust_boundary or '(unknown)'}"
        for entry in architecture.entry_points[:30]
    ]
    return "# ARCHITECTURE ENTRY POINTS\n" + "\n".join(rows)


def _falsification_context(
    index: RetrievalIndex | None,
    finding: Finding,
    architecture: ArchitectureMap,
    iteration: int,
    slice_evidence: StructuralSliceEvidence | None = None,
    resolution: FalsificationResolution | None = None,
) -> str:
    """Gather deterministic evidence with a genuinely broader strategy each round."""
    if index is None:
        return ""
    resolution = resolution or FalsificationResolution()
    sections: list[str] = []
    enclosing = index.find_enclosing(
        finding.file, finding.line_start, finding.line_end
    )
    if enclosing:
        sections.append(_format_context("ENCLOSING FUNCTION", enclosing[:2]))
    else:
        excerpt = index.file_excerpt(
            finding.file,
            finding.line_start,
            finding.line_end,
            context_lines=resolution.local_context_lines,
        )
        if excerpt is not None:
            sections.append(_format_context("LOCAL SOURCE", [excerpt]))
    if slice_evidence is None:
        slice_evidence = build_structural_slice(index, finding)
    if slice_evidence is not None:
        sections.append(slice_evidence.render())

    if iteration >= 2:
        related = []
        for info in enclosing[:2]:
            related.extend(index.find_callers(info.symbol))
            related.extend(index.find_callees(info.symbol))
        related.extend(
            index.find_similar_patterns(
                finding.citation_snippet,
                limit=resolution.related_result_base + iteration,
            )
        )
        if related:
            sections.append(_format_context("CALL/PATTERN EVIDENCE", related))

    if iteration >= 3:
        excerpt = index.file_excerpt(
            finding.file,
            finding.line_start,
            finding.line_end,
            context_lines=resolution.module_context_lines,
        )
        if excerpt is not None:
            sections.append(_format_context("MODULE CONTEXT", [excerpt]))
        sections.append(_architecture_context(architecture))
        reference_seed = "\n".join(
            [finding.citation_snippet, *(info.source for info in enclosing[:2])]
        )
        references = []
        for token in sorted(set(_REFERENCE_TOKEN_RE.findall(reference_seed)))[:6]:
            references.extend(index.find_text_references(token, limit=4))
        if references:
            sections.append(_format_context("CONFIG/REGISTRATION EVIDENCE", references))

    evidence = "\n\n# ---\n\n".join(section for section in sections if section)
    if not evidence:
        return ""
    return (
        f"# RETRIEVAL STRATEGY: {CONTEXT_VERSION}; tier={iteration}\n"
        f"{evidence}"
    )[:resolution.max_evidence_chars]


def _boundary_name(architecture: ArchitectureMap, finding: Finding) -> str:
    for tb in architecture.trust_boundaries:
        if tb.id == finding.trust_boundary_id:
            return tb.name
    return "(unmapped)"


def _verdict_prompt(finding: Finding, boundary: str, evidence_block: str) -> str:
    return (
        f"CANDIDATE FINDING\n"
        f"title: {finding.title}\n"
        f"file: {finding.file}\n"
        f"line_range: {finding.line_start}-{finding.line_end}\n"
        f"trust_boundary: {boundary}\n"
        f"source_lens: {finding.source_lens}\n"
        f"source_tool: {finding.source_tool}\n"
        f"citation:\n{finding.citation_snippet}\n"
        f"{evidence_block}"
    )


def _critique_prompt(finding: Finding, verdict: FalsificationOutcome, evidence_block: str) -> str:
    return (
        f"CANDIDATE FINDING\n"
        f"title: {finding.title}\n"
        f"file: {finding.file}\n"
        f"citation:\n{finding.citation_snippet}\n\n"
        f"YOUR VERDICT TO AUDIT\n"
        f"status: {verdict.status}\n"
        f"rationale: {verdict.rationale}\n"
        f"reachable: {verdict.reachable}\n"
        f"mitigating_control: {verdict.mitigating_control}\n"
        f"reported_confidence: {verdict.confidence}\n"
        f"\nEVIDENCE YOU ACTUALLY HAD:\n{evidence_block or '(no related context was retrieved)'}"
    )


def challenge_finding(
    finding: Finding,
    architecture: ArchitectureMap,
    llm: LLMClient,
    index: RetrievalIndex | None = None,
    config: Config | None = None,
    self_critique: bool = True,
    snapshot_commit: str | None = None,
    resolution: FalsificationResolution | None = None,
    evidence_observer: Callable[[int, str], None] | None = None,
    minimum_iterations: int = 1,
    persist_artifacts: bool = True,
) -> FalsificationOutcome:
    """Attempt to disprove one candidate finding via the bounded loop. Returns a verdict.

    Runs up to `config.falsify.max_iterations` observe-think-act-reflect rounds. A round
    commits only when the verdict is a confident, self-critique-upheld confirm/kill;
    otherwise the loop broadens its evidence and retries. On budget exhaustion it
    degrades to `unresolved`. Every round is persisted (when the finding has an id) so
    the reasoning trace survives for the review stage.

    `self_critique` gates the REFLECT step. The default (`True`) is the round-5 behavior
    (`falsification_selfcritique_v1`). Setting it `False` reconstructs the *immediately
    prior* falsify behavior — commit on a confident terminal verdict alone, with no
    reflect step — which the eval harness uses as the honest baseline to benchmark the
    net-new self-critique prompt against (it has no predecessor prompt file). It is an
    eval knob only; production callers leave it on.

    `resolution`, `evidence_observer`, `minimum_iterations`, and `persist_artifacts` are
    evaluation seams. Their defaults preserve production retrieval, early exit, and audit
    writes. Convergence evaluation disables artifact persistence and forces each profile to
    reach its declared tier; normal falsification does neither.
    """
    config = config or get_config()
    resolution = resolution or FalsificationResolution()
    threshold = config.llm.confidence_threshold
    max_iterations = max(1, config.falsify.max_iterations)
    minimum_iterations = max(1, min(minimum_iterations, max_iterations))
    boundary = _boundary_name(architecture, finding)
    slice_evidence = build_structural_slice(index, finding) if index is not None else None
    if persist_artifacts and slice_evidence is not None and finding.id is not None:
        claim = claim_from_slice(finding.id, slice_evidence, snapshot_commit)
        claim_id = db.upsert_security_claim(claim, config)
        claim = claim.model_copy(update={"id": claim_id})
        verification = verify_structural_claim(
            claim,
            index.snapshot_path if index is not None else None,
            snapshot_commit,
        )
        db.upsert_claim_verification(verification, config)

    last_verdict: FalsificationOutcome | None = None
    last_critique: SelfCritique | None = None

    for iteration in range(1, max_iterations + 1):
        # OBSERVE — gather evidence, broadening the retrieval window each round.
        evidence_block = _falsification_context(
            index, finding, architecture, iteration, slice_evidence, resolution
        )
        if evidence_observer is not None:
            evidence_observer(iteration, evidence_block)

        # THINK / ACT — form a verdict against the current evidence.
        verdict_completion = llm.call(
            module="falsify",
            prompt_version=PROMPT_VERSION,
            system=secure_system_prompt(PROMPT),
            user=delimit_repository_evidence(
                _verdict_prompt(finding, boundary, evidence_block)
            ),
            schema=FalsificationOutcome,
            context={
                "stage": "falsify", "repo_id": finding.repo_id,
                "finding_id": finding.id, "citation": finding.citation_snippet,
                "iteration": iteration, "resolution": resolution.name,
            },
        )
        verdict = verdict_completion.value

        # REFLECT — self-critique the verdict against the evidence before committing.
        if self_critique:
            critique_completion = llm.call(
                module="falsify",
                prompt_version=CRITIQUE_PROMPT_VERSION,
                system=secure_system_prompt(CRITIQUE_PROMPT),
                user=delimit_repository_evidence(
                    _critique_prompt(finding, verdict, evidence_block)
                ),
                schema=SelfCritique,
                context={
                    "stage": "falsify", "repo_id": finding.repo_id,
                    "finding_id": finding.id, "citation": finding.citation_snippet,
                    "iteration": iteration, "critique": True,
                    "resolution": resolution.name,
                },
            )
            critique = critique_completion.value
            upheld = critique.upholds and not critique_completion.low_confidence
        else:
            # Prior-version baseline: no reflect step. Recorded honestly in the trace so
            # the disabled critique is auditable rather than implied.
            critique = SelfCritique(
                upholds=True,
                concern="self-critique step disabled (prior-version eval baseline)",
                confidence=1.0,
            )
            upheld = True

        committed = (
            verdict.status in _TERMINAL
            and not verdict_completion.low_confidence
            and upheld
        )

        if persist_artifacts:
            _log_iteration(
                finding, iteration, evidence_block, verdict, critique, committed, config
            )
        last_verdict, last_critique = verdict, critique

        if committed and iteration >= minimum_iterations:
            return verdict

    # Budget exhausted without a confident, upheld verdict -> degrade to unresolved.
    return _unresolved(last_verdict, last_critique, max_iterations, threshold)


def _log_iteration(
    finding: Finding,
    iteration: int,
    evidence_block: str,
    verdict: FalsificationOutcome,
    critique: SelfCritique,
    committed: bool,
    config: Config,
) -> None:
    """Persist one round of the loop (skipped for unsaved findings in unit tests)."""
    if finding.id is None:
        return
    db.insert_falsification_iteration(
        FalsificationIteration(
            finding_id=finding.id,
            iteration=iteration,
            evidence=(evidence_block.strip() or "(no related context was retrieved)")[:2000],
            verdict_status=verdict.status,
            verdict_rationale=verdict.rationale,
            verdict_confidence=verdict.confidence,
            critique_upholds=critique.upholds,
            critique_note=critique.concern,
            committed=committed,
        ),
        config,
    )


def _unresolved(
    last_verdict: FalsificationOutcome | None,
    last_critique: SelfCritique | None,
    iterations: int,
    threshold: float,
) -> FalsificationOutcome:
    """Graceful degradation: the loop hit its budget without a confident, upheld verdict."""
    if last_verdict is None:  # unreachable in practice (>=1 iteration), defensive
        return FalsificationOutcome(
            status=FalsificationStatus.UNRESOLVED,
            rationale=f"Unresolved: no verdict produced within {iterations} iterations.",
        )
    critique_note = last_critique.concern if last_critique is not None else "n/a"
    return FalsificationOutcome(
        status=FalsificationStatus.UNRESOLVED,
        rationale=(
            f"Escalated to unresolved after {iterations} falsification iteration(s) without "
            f"a confident, self-critique-upheld verdict (confidence threshold {threshold:.2f}). "
            f"Last verdict was '{last_verdict.status}' "
            f"(confidence {last_verdict.confidence:.2f}): {last_verdict.rationale} "
            f"Self-critique: {critique_note}"
        ),
        reachable=last_verdict.reachable,
        mitigating_control=last_verdict.mitigating_control,
        confidence=last_verdict.confidence,
    )


class FalsificationRun(list[FalsificationOutcome]):
    """List-compatible outcomes with the number deferred by this run's budget."""

    def __init__(
        self, outcomes: list[FalsificationOutcome], deferred_count: int, *,
        pending_count: int = 0, minimum_calls_per_finding: int = 0,
        reserved_calls_per_finding: int = 0, remaining_call_capacity: int | None = None,
    ):
        super().__init__(outcomes)
        self.deferred_count = deferred_count
        self.pending_count = pending_count
        self.minimum_calls_per_finding = minimum_calls_per_finding
        self.reserved_calls_per_finding = reserved_calls_per_finding
        self.remaining_call_capacity = remaining_call_capacity


def challenge(
    repo_id: str,
    config: Config | None = None,
    llm: LLMClient | None = None,
    index: RetrievalIndex | None = None,
    self_critique: bool = True,
) -> FalsificationRun:
    """Run the falsification pass over a repo's not-yet-examined findings, within budget.

    Repo-level entry point. Candidates are the findings the loop has not examined yet —
    `unresolved` (fresh from detect) or `deferred` (set aside by a prior run) with no
    logged iterations. They are taken in **triage priority order** — highest
    P(actionable) first — while a bounded run with at least two slots reserves configured
    capacity for untriaged findings (e.g. LLM-lens findings) so a large deterministic queue
    cannot starve novel work. Within the untriaged stream, severity then confidence orders
    candidates.

    `config.falsify.max_findings_per_run` caps how many get the (expensive) loop this
    run. The active pipeline's remaining provider-call capacity can lower that cap using
    the full configured iteration/retry envelope. Candidates beyond the effective cap are
    persisted `deferred` — never dropped — and resumed by a later run. `0` disables only
    the stage-local cap. Findings the loop already examined (they carry iteration rows)
    are left untouched, so a resumed run never re-litigates a verdict it already reached.

    `self_critique` is forwarded to `challenge_finding` (default on = round-5 behavior);
    the eval harness sets it `False` to benchmark the reflect step against its prior.
    """
    config = config or get_config()
    llm = llm or get_llm_client(config)
    snapshot_path, commit = latest_snapshot(config, repo_id)
    architecture = load_architecture(repo_id, commit, config)
    index = index or RetrievalIndex().build(snapshot_path)

    already_examined = db.finding_ids_with_iterations(repo_id, config)
    triage = {tr.finding_id: tr for tr in db.list_triage_results(repo_id, config)}
    pending = [
        f for f in db.list_findings(repo_id, config)
        if f.falsification_status in _PENDING_STATUSES and f.id not in already_examined
    ]
    pending = _budget_order(pending, triage)

    configured_budget = config.falsify.max_findings_per_run
    remaining_calls = remaining_pipeline_call_capacity(config)
    logical_calls_per_iteration = 2 if self_critique else 1
    minimum_calls = logical_calls_per_iteration
    # Reserve the full configured iteration/retry envelope. A successful verdict often
    # exits earlier, but scheduling against the optimistic case would allow a queue of
    # individually valid retries to consume the run ceiling midway through a finding.
    reserved_calls = (
        logical_calls_per_iteration
        * max(1, config.falsify.max_iterations)
        * (config.llm.max_retries + 1)
    )
    capacity_budget = (
        remaining_calls // reserved_calls if remaining_calls is not None else None
    )
    budgets = [
        value for value in (configured_budget or None, capacity_budget)
        if value is not None
    ]
    budget = min(budgets) if budgets else 0
    if budgets:
        selected, deferred = _budget_partition(
            pending, triage, budget, config.falsify.min_untriaged_per_run
        )
    else:
        selected, deferred = pending, []

    outcomes: list[FalsificationOutcome] = []
    for finding in selected:
        outcome = challenge_finding(
            finding,
            architecture,
            llm,
            index,
            config,
            self_critique=self_critique,
            snapshot_commit=commit,
        )
        db.update_falsification(finding.id, outcome.status, outcome.rationale, config)
        outcomes.append(outcome)

    # Everything past the budget cutoff is set aside explicitly (null-result logging),
    # not silently skipped, so review/analyze can tell "not yet examined" from a verdict.
    for finding in deferred:
        db.update_falsification(
            finding.id, FalsificationStatus.DEFERRED,
            f"Deferred: outside this falsify run's safe budget of {budget} finding(s); ranked "
            f"below the cutoff and will be resumed by a later run.",
            config,
        )
    return FalsificationRun(
        outcomes, len(deferred), pending_count=len(pending),
        minimum_calls_per_finding=minimum_calls,
        reserved_calls_per_finding=reserved_calls,
        remaining_call_capacity=remaining_calls,
    )


_PENDING_STATUSES = (FalsificationStatus.UNRESOLVED, FalsificationStatus.DEFERRED)


def _budget_order(
    pending: list[Finding], triage: dict[int, TriageResult]
) -> list[Finding]:
    """Order candidates for the falsify budget: triaged first, then untriaged fallback.

    Tier 0 — findings triage scored — sorts by P(actionable) descending (rank as a
    tiebreak): the highest-value deterministic-tool findings are falsified first. Tier 1
    — findings with no triage result (LLM-lens findings) — falls back to severity
    descending, then confidence, so nothing untriaged is starved arbitrarily.
    """
    def key(f: Finding):
        tr = triage.get(f.id)
        if tr is not None:
            return (0, -tr.p_actionable, tr.rank)
        return (1, -severity_rank(f.severity), -f.confidence)

    return sorted(pending, key=key)


def _budget_partition(
    pending: list[Finding],
    triage: dict[int, TriageResult],
    budget: int,
    min_untriaged: int,
) -> tuple[list[Finding], list[Finding]]:
    """Select a bounded queue while reserving capacity for novel/untriaged findings.

    A run with fewer than two slots cannot serve both streams, so it retains the existing
    best-first order. Otherwise, when both streams exist, up to ``min_untriaged`` slots are
    reserved for the highest-severity/confidence untriaged findings. Remaining slots keep
    the calibrated P(actionable) ordering. Every unselected finding remains deferred and
    resumable; this changes scheduling only, never finding status semantics.
    """
    if budget < 2 or min_untriaged <= 0:
        return pending[:budget], pending[budget:]

    triaged = [finding for finding in pending if finding.id in triage]
    untriaged = [finding for finding in pending if finding.id not in triage]
    if not triaged or not untriaged:
        return pending[:budget], pending[budget:]

    reserve = min(min_untriaged, len(untriaged), budget - 1)
    selected = [*triaged[: budget - reserve], *untriaged[:reserve]]
    # If one stream cannot fill its allocation, use the globally ordered remainder.
    selected_ids = {finding.id for finding in selected}
    for finding in pending:
        if len(selected) >= budget:
            break
        if finding.id not in selected_ids:
            selected.append(finding)
            selected_ids.add(finding.id)
    deferred = [finding for finding in pending if finding.id not in selected_ids]
    return selected, deferred
