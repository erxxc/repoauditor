"""Assemble the triage classifier's training corpus: synthetic teacher + real labels.

The classifier starts on a synthetic corpus (cold start) and shifts onto real accumulated
`TriageLabel` data as it grows. This module builds the combined `(X, y)` plus the
`sample_weight` and `real_mask` that encode *how much* the model should trust synthetic vs.
real — the principled, documented blend defined in `config.TriageConfig`:

  synthetic share of the training mass = pseudocount / (pseudocount + n_real)

so real data is never permanently co-equal with synthetic — its influence grows with its
count and synthetic's fades, and past `synthetic_cutoff_labels` real rows the synthetic pool
is dropped outright. `real_mask` marks the real rows so `TriageClassifier.train` can carve a
*real* held-out split for honest precision-recall/Brier once enough real labels exist.

Real labels also feed the classifier a second way, upstream of here: via the per-rule
Beta-Binomial prior mean and historical FP-rate features (`triage/priors.py`,
`triage/features.py`). This module adds the third, most direct channel — real labelled
feature rows in the training set itself.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from ..config import Config, get_config
from ..store import db
from ..store.models import TriageLabelSource
from . import synthetic
from .features import FEATURE_NAMES


@dataclass
class TrainingCorpus:
    """Combined synthetic+real corpus with per-row weights and a real/synthetic mask."""

    X: np.ndarray
    y: np.ndarray
    sample_weight: np.ndarray
    real_mask: np.ndarray          # True for real rows (for a real held-out eval split)
    engagement_groups: np.ndarray  # repo id for real rows; empty string for synthetic rows
    evaluation_mask: np.ndarray    # manual/review labels eligible for honest evaluation
    label_source_counts: dict[str, int]
    n_real: int
    n_synthetic: int
    synthetic_share: float         # synthetic's fraction of total effective training mass
    synthetic_dropped: bool        # True once n_real >= cutoff (synthetic retired)


def evaluation_family(engagement: str, config: Config) -> str:
    """Return the evaluation-only family id for one persisted engagement."""
    return config.triage.evaluation_family_overrides.get(engagement, engagement)


def load_real_examples(
    config: Config | None = None,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, dict[str, int]]:
    """Real labelled feature rows from the store, filtered to the current feature schema.

    Rows whose stored `feature_names` don't match the current `FEATURE_NAMES` are dropped
    (a schema change is detected, never silently column-misaligned). Returns `(X_real,
    y_real)` with `X_real` shaped `(n, len(FEATURE_NAMES))` (possibly n=0).
    """
    config = config or get_config()
    width = len(FEATURE_NAMES)
    xs: list[list[float]] = []
    ys: list[int] = []
    groups: list[str] = []
    evaluation_eligible: list[bool] = []
    source_counts: dict[str, int] = {}
    for features, names, actionable, engagement, source in db.list_real_training_examples(config):
        if names != FEATURE_NAMES or len(features) != width:
            continue
        xs.append([float(v) for v in features])
        ys.append(int(actionable))
        groups.append(evaluation_family(engagement, config))
        evaluation_eligible.append(
            source in (TriageLabelSource.MANUAL, TriageLabelSource.DERIVED_REVIEW)
        )
        source_counts[str(source)] = source_counts.get(str(source), 0) + 1
    if not xs:
        return (np.empty((0, width), dtype=float), np.empty((0,), dtype=int),
                np.empty((0,), dtype=object), np.empty((0,), dtype=bool), {})
    return (
        np.asarray(xs, dtype=float), np.asarray(ys, dtype=int),
        np.asarray(groups, dtype=object), np.asarray(evaluation_eligible, dtype=bool),
        source_counts,
    )


def synthetic_share(n_real: int, config: Config | None = None) -> float:
    """Synthetic's fraction of the training mass for a given real-label count (documented).

    Beta-Binomial-style shrinkage: pseudocount / (pseudocount + n_real), forced to 0 once
    `n_real` reaches the cutoff. Exposed as a pure function so the blend is unit-testable.
    """
    config = config or get_config()
    tc = config.triage
    if n_real >= tc.synthetic_cutoff_labels:
        return 0.0
    return tc.synthetic_pseudocount / (tc.synthetic_pseudocount + n_real)


def assemble_training_data(
    config: Config | None = None, seed: int = 0
) -> TrainingCorpus:
    """Build the combined corpus + shrinkage weights for one triage training run."""
    config = config or get_config()
    tc = config.triage

    ds = synthetic.generate(n=tc.synthetic_corpus_size, seed=seed)
    Xs, ys = ds.X, ds.y
    Xr, yr, groups_r, eval_r, source_counts = load_real_examples(config)
    n_syn, n_real = len(ys), len(yr)

    dropped = n_real >= tc.synthetic_cutoff_labels
    if dropped or n_syn == 0:
        # Real data fully specifies the problem — retire the synthetic teacher.
        X, y = Xr, yr
        sample_weight = np.ones(n_real, dtype=float)
        real_mask = np.ones(n_real, dtype=bool)
        groups = groups_r
        evaluation_mask = eval_r
        share = 0.0
    elif n_real == 0:
        # Cold start — synthetic only.
        X, y = Xs, ys
        sample_weight = np.ones(n_syn, dtype=float)
        real_mask = np.zeros(n_syn, dtype=bool)
        groups = np.full(n_syn, "", dtype=object)
        evaluation_mask = np.zeros(n_syn, dtype=bool)
        share = 1.0
    else:
        # Blend: real rows weight 1.0; the whole synthetic pool shares `pseudocount`, so
        # synthetic's effective mass is capped and its share decays as real accumulates.
        syn_weight = tc.synthetic_pseudocount / n_syn
        X = np.vstack([Xs, Xr])
        y = np.concatenate([ys, yr])
        sample_weight = np.concatenate([
            np.full(n_syn, syn_weight, dtype=float),
            np.ones(n_real, dtype=float),
        ])
        real_mask = np.concatenate([
            np.zeros(n_syn, dtype=bool), np.ones(n_real, dtype=bool)
        ])
        groups = np.concatenate([np.full(n_syn, "", dtype=object), groups_r])
        evaluation_mask = np.concatenate([np.zeros(n_syn, dtype=bool), eval_r])
        share = tc.synthetic_pseudocount / (tc.synthetic_pseudocount + n_real)

    return TrainingCorpus(
        X=X, y=y, sample_weight=sample_weight, real_mask=real_mask,
        engagement_groups=groups,
        evaluation_mask=evaluation_mask,
        label_source_counts=source_counts,
        n_real=n_real, n_synthetic=(0 if dropped else n_syn),
        synthetic_share=share, synthetic_dropped=dropped,
    )
