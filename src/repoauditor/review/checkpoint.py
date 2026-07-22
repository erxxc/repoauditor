"""Blocking human-review checkpoint — a maker-checker (four-eyes) control.

Implements the maker-checker principle: work the automated pipeline (the *maker*)
cannot resolve is held for a human *checker* before it is allowed downstream. A finding
is held when it is `unresolved` after falsify/ or normalize/, or when triage/ is too
uncertain about it (winning-class probability below `config.review.triage_confidence_
threshold`). Each held finding gets a `ReviewRequest` carrying the reason plus the
evidence a reviewer needs — the citation, the trust-boundary context, and the relevant
stage's own reasoning trace (falsification iterations, adjudication debate, or triage
attribution).

The checkpoint is genuinely blocking: `analyzable_findings` (the query an analyze-style
stage uses in place of `db.list_findings`) excludes any finding whose review request has
no releasing `ReviewDecision`. This module never auto-approves — recording a decision is
`review/audit.py`, driven by a human.
"""

from __future__ import annotations

from ..config import Config, get_config
from ..store import db
from ..store.models import (
    FalsificationStatus,
    Finding,
    ReviewRequest,
    TriageResult,
)


def _boundary_names(repo_id: str, config: Config) -> dict[int, str]:
    return {tb.id: tb.name for tb in db.list_trust_boundaries(repo_id, config) if tb.id is not None}


def _base_evidence(finding: Finding, boundaries: dict[int, str]) -> dict:
    """The context common to every held finding: citation + trust-boundary + origin."""
    return {
        "citation": finding.citation_snippet,
        "trust_boundary": boundaries.get(finding.trust_boundary_id, "(unmapped)"),
        "severity": str(finding.severity),
        "source": finding.source_tool or finding.source_lens,
        "description": finding.description,
    }


def _unresolved_request(
    finding: Finding, boundaries: dict[int, str], config: Config
) -> ReviewRequest:
    """Build a review request for an `unresolved` finding, attaching its stage trace.

    The stage is inferred from which trace exists: a falsification iteration trace means
    the challenger loop exhausted its budget; an `unresolved` adjudication debate means
    normalize could not reach consensus. Either trace is attached so the reviewer sees
    the reasoning, not just the verdict.
    """
    evidence = _base_evidence(finding, boundaries)

    iterations = db.list_falsification_iterations(finding.id, config)
    if iterations:
        evidence["falsification_trace"] = [
            {
                "iteration": it.iteration,
                "verdict": str(it.verdict_status),
                "verdict_confidence": it.verdict_confidence,
                "verdict_rationale": it.verdict_rationale,
                "critique_upholds": it.critique_upholds,
                "critique_note": it.critique_note,
                "evidence": it.evidence,
                "committed": it.committed,
            }
            for it in iterations
        ]
        return ReviewRequest(
            repo_id=finding.repo_id, finding_id=finding.id, stage="falsify",
            reason=(
                f"Falsification could not confirm or kill this finding within "
                f"{len(iterations)} iteration(s); it remained unresolved."
            ),
            evidence=evidence,
        )

    debate = db.get_adjudication_debate_for_region(
        finding.repo_id, finding.file, finding.line_start, finding.line_end, config
    )
    if debate is not None and debate.outcome == "unresolved":
        evidence["debate"] = [
            {
                "source": p.source_name, "source_type": str(p.source_type),
                "severity": str(p.severity), "reasoning": p.reasoning,
            }
            for p in debate.positions
        ]
        evidence["synthesis_rationale"] = debate.synthesis_rationale
        return ReviewRequest(
            repo_id=finding.repo_id, finding_id=finding.id, stage="normalize",
            reason="Sources disagreed on severity and adjudication reached no consensus.",
            evidence=evidence,
        )

    return ReviewRequest(
        repo_id=finding.repo_id, finding_id=finding.id, stage="falsify",
        reason="Finding is unresolved and could not be resolved automatically.",
        evidence=evidence,
    )


def _triage_request(
    result: TriageResult, finding: Finding, boundaries: dict[int, str]
) -> ReviewRequest:
    """Build a review request for a triage result the classifier is too uncertain about."""
    confidence = max(result.p_actionable, 1.0 - result.p_actionable)
    evidence = _base_evidence(finding, boundaries)
    evidence["triage"] = {
        "p_actionable": result.p_actionable,
        "winning_class_confidence": confidence,
        "rank": result.rank,
        "model": result.model_name,
        "attributions": result.attributions,
    }
    return ReviewRequest(
        repo_id=finding.repo_id, finding_id=finding.id, stage="triage",
        reason=(
            f"Triage classifier is uncertain (P(actionable)={result.p_actionable:.2f}, "
            f"winning-class confidence {confidence:.2f}) — below the review threshold."
        ),
        evidence=evidence,
    )


def raise_review_requests(repo_id: str, config: Config | None = None) -> list[ReviewRequest]:
    """Open review requests for every finding the pipeline could not resolve.

    Scans the repo's findings for `unresolved` status and its triage results for
    classifier uncertainty, and upserts one `ReviewRequest` per held finding (idempotent
    — re-running refreshes, it does not duplicate). An `unresolved` finding takes
    precedence over a merely-uncertain triage result for the same finding. Returns the
    requests that are now open.
    """
    config = config or get_config()
    boundaries = _boundary_names(repo_id, config)
    findings = db.list_findings(repo_id, config)
    findings_by_id = {f.id: f for f in findings}

    # Build requests keyed by finding_id so `unresolved` (added last) wins over triage.
    requests: dict[int, ReviewRequest] = {}

    threshold = config.review.triage_confidence_threshold
    for result in db.list_triage_results(repo_id, config):
        finding = findings_by_id.get(result.finding_id)
        if finding is None:
            continue
        confidence = max(result.p_actionable, 1.0 - result.p_actionable)
        if confidence < threshold:
            requests[result.finding_id] = _triage_request(result, finding, boundaries)

    for finding in findings:
        if finding.falsification_status is FalsificationStatus.UNRESOLVED:
            requests[finding.id] = _unresolved_request(finding, boundaries, config)

    for request in requests.values():
        db.upsert_review_request(request, config)
    return list(requests.values())


def open_review_requests(repo_id: str, config: Config | None = None) -> list[ReviewRequest]:
    """Review requests still awaiting a decision — the reviewer's queue."""
    config = config or get_config()
    return [
        request
        for request in db.list_review_requests(repo_id, config)
        if db.latest_review_decision(request.id, config) is None
    ]


def _trace_summary(evidence: dict) -> str:
    """One-line summary of whichever stage trace a held finding carries (if any)."""
    if "falsification_trace" in evidence:
        return f"falsify — {len(evidence['falsification_trace'])} iteration(s), unresolved"
    if "debate" in evidence:
        rationale = evidence.get("synthesis_rationale") or ""
        return (f"normalize — {len(evidence['debate'])} conflicting positions"
                + (f"; {rationale}" if rationale else ""))
    if "triage" in evidence:
        t = evidence["triage"]
        return (f"triage — P(actionable)={t.get('p_actionable')}, "
                f"winning-class confidence={t.get('winning_class_confidence')}")
    return ""


def render_open_requests(repo_id: str, config: Config | None = None) -> str:
    """Human-readable summary of the open review queue — what `review list` prints.

    Rendering lives here (not in `cli.py`) so the CLI stays a thin arg-parse-and-call shell,
    exactly as the report projections return their rendered string.
    """
    config = config or get_config()
    requests = open_review_requests(repo_id, config)
    if not requests:
        return f"No open review requests for {repo_id}."

    lines = [f"Open review requests for {repo_id} ({len(requests)}):", ""]
    for r in requests:
        ev = r.evidence or {}
        lines.append(f"- request #{r.id}  ·  finding #{r.finding_id}  ·  stage={r.stage}")
        lines.append(f"    reason: {r.reason}")
        lines.append(
            f"    severity={ev.get('severity', '?')}  source={ev.get('source', '?')}  "
            f"boundary={ev.get('trust_boundary', '?')}"
        )
        if ev.get("citation"):
            lines.append(f"    citation: {ev['citation']}")
        trace = _trace_summary(ev)
        if trace:
            lines.append(f"    trace: {trace}")
        lines.append("")
    lines.append(
        "Decide with:  repoauditor review decide "
        f"{repo_id} <request-id> --decision=confirm|dismiss --rationale=\"...\""
    )
    return "\n".join(lines)


def is_blocked(finding_id: int, config: Config | None = None) -> bool:
    """True if this finding is held at the checkpoint (open request, not yet released).

    Blocked = has a review request whose effective decision is not `confirm` (no
    decision yet, or a `dismiss`). This mirrors what `db.list_analyzable_findings`
    filters on.
    """
    config = config or get_config()
    request = db.get_review_request(finding_id, config)
    if request is None:
        return False
    decision = db.latest_review_decision(request.id, config)
    return decision is None or decision.disposition.value != "confirm"


def analyzable_findings(repo_id: str, config: Config | None = None) -> list[Finding]:
    """Findings released for analysis — the checkpoint applied.

    This is the query an analyze-style stage should use in place of `db.list_findings`:
    it drops findings still blocked at the review checkpoint. (Wiring `analyze/` to call
    this is deferred — this session builds the gate; analyze/ business logic is untouched.)
    """
    config = config or get_config()
    return db.list_analyzable_findings(repo_id, config)
