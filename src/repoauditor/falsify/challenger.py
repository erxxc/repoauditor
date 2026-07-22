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

from pathlib import Path

from ..config import Config, get_config
from ..ingest import latest_snapshot
from ..llm import LLMClient, get_llm_client
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

# Re-exported: the model's structured output shape for a falsification verdict.
from .outcome import FalsificationOutcome, SelfCritique

PROMPT_VERSION = "falsification_v2"
PROMPT = (Path(__file__).parent / "prompts" / f"{PROMPT_VERSION}.md").read_text()

CRITIQUE_PROMPT_VERSION = "falsification_selfcritique_v1"
CRITIQUE_PROMPT = (
    Path(__file__).parent / "prompts" / f"{CRITIQUE_PROMPT_VERSION}.md"
).read_text()

_TERMINAL = (FalsificationStatus.CONFIRMED, FalsificationStatus.KILLED)


def _mitigating_context(index: RetrievalIndex | None, finding: Finding, limit: int) -> str:
    """Related call sites that might mitigate the finding (empty if no index).

    `limit` grows with the iteration so later rounds pull broader context before the
    loop is allowed to give up — the confidence-gated broader-retrieval discipline,
    applied inside the falsification loop.
    """
    if index is None:
        return ""
    similar = index.find_similar_patterns(finding.citation_snippet, limit=limit)
    if not similar:
        return ""
    blocks = [
        f"# {info.symbol} ({info.file}:{info.line_start})\n{info.source}"
        for info in similar
    ]
    return "\n\n# --- related code that may already mitigate this ---\n" + "\n\n".join(blocks)


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
    """
    config = config or get_config()
    threshold = config.llm.confidence_threshold
    max_iterations = max(1, config.falsify.max_iterations)
    boundary = _boundary_name(architecture, finding)

    last_verdict: FalsificationOutcome | None = None
    last_critique: SelfCritique | None = None

    for iteration in range(1, max_iterations + 1):
        # OBSERVE — gather evidence, broadening the retrieval window each round.
        evidence_block = _mitigating_context(index, finding, limit=2 + iteration)

        # THINK / ACT — form a verdict against the current evidence.
        verdict_completion = llm.call(
            module="falsify",
            prompt_version=PROMPT_VERSION,
            system=PROMPT,
            user=_verdict_prompt(finding, boundary, evidence_block),
            schema=FalsificationOutcome,
            context={
                "stage": "falsify", "repo_id": finding.repo_id,
                "finding_id": finding.id, "citation": finding.citation_snippet,
                "iteration": iteration,
            },
        )
        verdict = verdict_completion.value

        # REFLECT — self-critique the verdict against the evidence before committing.
        if self_critique:
            critique_completion = llm.call(
                module="falsify",
                prompt_version=CRITIQUE_PROMPT_VERSION,
                system=CRITIQUE_PROMPT,
                user=_critique_prompt(finding, verdict, evidence_block),
                schema=SelfCritique,
                context={
                    "stage": "falsify", "repo_id": finding.repo_id,
                    "finding_id": finding.id, "citation": finding.citation_snippet,
                    "iteration": iteration, "critique": True,
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

        _log_iteration(finding, iteration, evidence_block, verdict, critique, committed, config)
        last_verdict, last_critique = verdict, critique

        if committed:
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

    def __init__(self, outcomes: list[FalsificationOutcome], deferred_count: int):
        super().__init__(outcomes)
        self.deferred_count = deferred_count


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
    logged iterations. They are taken in **triage priority order** — triaged findings
    first, highest P(actionable) first (the triage->falsify seam the scaffold calls for),
    then untriaged findings (e.g. LLM-lens findings, which triage does not score) by
    severity then confidence.

    `config.falsify.max_findings_per_run` caps how many get the (expensive) loop this
    run. Candidates beyond the cap are persisted `deferred` — never dropped — and resumed
    by a later run. `0` means unlimited (challenge every candidate). Findings the loop
    already examined (they carry iteration rows) are left untouched, so a resumed run
    never re-litigates a verdict it already reached.

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

    budget = config.falsify.max_findings_per_run
    if budget and budget > 0:
        selected, deferred = pending[:budget], pending[budget:]
    else:
        selected, deferred = pending, []

    outcomes: list[FalsificationOutcome] = []
    for finding in selected:
        outcome = challenge_finding(finding, architecture, llm, index, config,
                                    self_critique=self_critique)
        db.update_falsification(finding.id, outcome.status, outcome.rationale, config)
        outcomes.append(outcome)

    # Everything past the budget cutoff is set aside explicitly (null-result logging),
    # not silently skipped, so review/analyze can tell "not yet examined" from a verdict.
    for finding in deferred:
        db.update_falsification(
            finding.id, FalsificationStatus.DEFERRED,
            f"Deferred: outside this falsify run's budget of {budget} finding(s); ranked "
            f"below the cutoff and will be resumed by a later run.",
            config,
        )
    return FalsificationRun(outcomes, len(deferred))


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
