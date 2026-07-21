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
from ..store.models import FalsificationIteration, FalsificationStatus, Finding
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
) -> FalsificationOutcome:
    """Attempt to disprove one candidate finding via the bounded loop. Returns a verdict.

    Runs up to `config.falsify.max_iterations` observe-think-act-reflect rounds. A round
    commits only when the verdict is a confident, self-critique-upheld confirm/kill;
    otherwise the loop broadens its evidence and retries. On budget exhaustion it
    degrades to `unresolved`. Every round is persisted (when the finding has an id) so
    the reasoning trace survives for the review stage.
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


def challenge(
    repo_id: str,
    config: Config | None = None,
    llm: LLMClient | None = None,
    index: RetrievalIndex | None = None,
) -> list[FalsificationOutcome]:
    """Run the falsification pass over every unresolved finding for a repo.

    Repo-level entry point: challenges each unresolved finding and persists the
    verdict + reason back to the store (killed findings kept, not deleted).
    """
    config = config or get_config()
    llm = llm or get_llm_client(config)
    snapshot_path, commit = latest_snapshot(config, repo_id)
    architecture = load_architecture(repo_id, commit, config)
    index = index or RetrievalIndex().build(snapshot_path)

    outcomes: list[FalsificationOutcome] = []
    for finding in db.list_findings(repo_id, config):
        if finding.falsification_status is not FalsificationStatus.UNRESOLVED:
            continue
        outcome = challenge_finding(finding, architecture, llm, index, config)
        db.update_falsification(finding.id, outcome.status, outcome.rationale, config)
        outcomes.append(outcome)
    return outcomes
