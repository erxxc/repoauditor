"""Per-rule Beta-Binomial prior for cold-start P(actionable), with Bayesian shrinkage.

Implements the Beta-Binomial conjugate model: a SAST rule's actionable (true-positive)
rate is Bernoulli(p); the analyst labels in `TriageLabel` are the observations; a
Beta(alpha0, beta0) prior gives the posterior Beta(alpha0 + a, beta0 + (n - a)) whose
mean is the shrinkage estimator

    E[p | data] = (alpha0 + a) / (alpha0 + beta0 + n)

With no labels (n = 0) this is the prior mean alpha0/(alpha0+beta0); as labels
accumulate it shrinks smoothly toward the observed actionable fraction a/n. The
strength of the prior (alpha0 + beta0 pseudo-observations) controls how many real
labels it takes to move the estimate — that hyperparameter choice is documented and
*sourced* in `priors.yaml` (triage.global_actionable_prior), not hardcoded here, per
the "no unsourced priors" rule.

This module never touches SQLite directly; it reads/writes labels and priors only
through `store/db.py`.
"""

from __future__ import annotations

from ..config import Config, get_config
from ..store import db
from ..store.models import RulePrior


def global_prior(config: Config | None = None) -> tuple[float, float, str]:
    """Return the sourced cold-start (alpha0, beta0, source) from priors.yaml."""
    config = config or get_config()
    bp = config.priors.triage.global_actionable_prior
    return bp.alpha, bp.beta, bp.source


def compute_rule_prior(rule_id: str, config: Config | None = None) -> RulePrior:
    """Compute the current Beta-Binomial prior for a rule from stored labels.

    Reads every `TriageLabel` for the rule (across engagements — the classifier learns
    cross-engagement), folds them into the sourced global Beta prior, and returns the
    posterior as a `RulePrior`. Pure read; does not persist. Posterior mean is the
    shrinkage estimate used as the `rule_prior_mean` feature and as the cold-start
    P(actionable) when the classifier has no better signal.
    """
    config = config or get_config()
    alpha0, beta0, source = global_prior(config)
    labels = db.list_triage_labels(rule_id, config)
    n = len(labels)
    a = sum(1 for label in labels if label.actionable)
    return RulePrior(
        rule_id=rule_id,
        alpha=alpha0 + a,
        beta=beta0 + (n - a),
        observed_actionable=a,
        observed_total=n,
        prior_source=source,
    )


def refresh_rule_priors(
    rule_ids: list[str], config: Config | None = None
) -> dict[str, RulePrior]:
    """Recompute and persist priors for a set of rules; return them keyed by rule_id.

    Called at the start of a triage run so the feature context reflects the latest
    labels. Idempotent: each rule's row is upserted.
    """
    config = config or get_config()
    priors: dict[str, RulePrior] = {}
    for rule_id in set(rule_ids):
        prior = compute_rule_prior(rule_id, config)
        db.upsert_rule_prior(prior, config)
        priors[rule_id] = prior
    return priors


def historical_fp_rate(rule_id: str, config: Config | None = None) -> tuple[float, int]:
    """Observed false-positive fraction for a rule and the #labels behind it.

    Returns (fp_rate, label_count). With no labels, (0.0, 0) — the classifier reads a
    zero FP-rate with a zero label-count (via `rule_label_count_log`) and can learn to
    discount unlabelled rules rather than trusting a spurious 0.
    """
    labels = db.list_triage_labels(rule_id, config)
    n = len(labels)
    if n == 0:
        return 0.0, 0
    fps = sum(1 for label in labels if not label.actionable)
    return fps / n, n
