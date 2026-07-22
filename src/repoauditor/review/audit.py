"""Review decisions — an append-only (WORM) audit trail.

Implements a write-once audit log: a `ReviewDecision` is never edited or deleted once
recorded. A correction is a *new* decision row that references the one it supersedes
(`supersedes_id`), so the full history — who ruled what, when, and how it was later
overridden — is always reconstructable. The effective ruling for a request is simply
its most recent decision.

These are the CLI-callable primitives a human reviewer drives; they are intentionally
NOT wired into `cli.py` yet (this session builds the mechanism, not the command).
"""

from __future__ import annotations

from ..config import Config, get_config
from ..store import db
from ..store.models import ReviewDecision, ReviewDisposition


def record_decision(
    review_request_id: int,
    reviewer: str,
    disposition: ReviewDisposition | str,
    rationale: str,
    supersedes_id: int | None = None,
    config: Config | None = None,
) -> ReviewDecision:
    """Record a reviewer's ruling on a held finding (append-only).

    `disposition` is `confirm` (release the finding to analysis) or `dismiss` (keep it in
    the store for the record but withhold it, like a killed candidate). `rationale` is
    mandatory. Raises if the request does not exist, or if `supersedes_id` is given but
    does not belong to the same request (a correction must correct *this* request's
    history, never edit another's).
    """
    config = config or get_config()
    disposition = ReviewDisposition(disposition)
    if not rationale or not rationale.strip():
        raise ValueError("a review decision must carry a rationale")

    if db.get_review_request_by_id(review_request_id, config) is None:
        raise ValueError(f"no review request with id {review_request_id}")
    if supersedes_id is not None:
        prior_ids = {d.id for d in db.list_review_decisions(review_request_id, config)}
        if supersedes_id not in prior_ids:
            raise ValueError(
                f"supersedes_id {supersedes_id} is not a prior decision of "
                f"request {review_request_id}"
            )

    decision = ReviewDecision(
        review_request_id=review_request_id,
        disposition=disposition,
        reviewer=reviewer,
        rationale=rationale,
        supersedes_id=supersedes_id,
    )
    decision_id = db.insert_review_decision(decision, config)
    return decision.model_copy(update={"id": decision_id})


def correct_decision(
    prior_decision_id: int,
    reviewer: str,
    disposition: ReviewDisposition | str,
    rationale: str,
    config: Config | None = None,
) -> ReviewDecision:
    """Override an earlier ruling with a new one — never an edit, always a new row.

    Looks up the request the prior decision belongs to and records a fresh decision that
    supersedes it. The original row is left untouched, preserving the audit trail.
    """
    config = config or get_config()
    prior = db.get_review_decision_by_id(prior_decision_id, config)
    if prior is None:
        raise ValueError(f"no review decision with id {prior_decision_id}")
    return record_decision(
        review_request_id=prior.review_request_id,
        reviewer=reviewer,
        disposition=disposition,
        rationale=rationale,
        supersedes_id=prior_decision_id,
        config=config,
    )


def decide(
    repo_id: str,
    request_id: int,
    disposition: ReviewDisposition | str,
    rationale: str,
    reviewer: str,
    config: Config | None = None,
) -> ReviewDecision:
    """Record a decision on a held finding, validating the request belongs to `repo_id`.

    Thin repo-aware wrapper over `record_decision` so the `review decide` CLI command stays
    logic-free: it just parses args and calls here. The repo check catches deciding a request
    from the wrong repo before an append-only decision row is written.
    """
    config = config or get_config()
    request = db.get_review_request_by_id(request_id, config)
    if request is None:
        raise ValueError(f"no review request with id {request_id}")
    if request.repo_id != repo_id:
        raise ValueError(
            f"review request {request_id} belongs to repo '{request.repo_id}', not '{repo_id}'"
        )
    return record_decision(request_id, reviewer, disposition, rationale, config=config)


def decision_history(review_request_id: int, config: Config | None = None) -> list[ReviewDecision]:
    """The full, ordered ruling history for a request (oldest first)."""
    config = config or get_config()
    return db.list_review_decisions(review_request_id, config)


def effective_decision(
    review_request_id: int, config: Config | None = None
) -> ReviewDecision | None:
    """The ruling currently in force for a request (its latest decision), or None."""
    config = config or get_config()
    return db.latest_review_decision(review_request_id, config)
