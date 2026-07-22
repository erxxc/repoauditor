"""Closed-loop eval regression gate.

Every golden-harness run is persisted as an `EvalRun` (prompt versions per stage,
precision/recall against the benchmark corpus). `record_and_check` compares a new run
against the immediately prior run for the same lineage; if precision or recall
regressed, it records the run with `regressed_from_prior=True` **and raises** —
the point is that a regressed prompt version cannot quietly become the one in use.

The stage prompt versions are read from the stages themselves, so this record always
reflects the prompts actually in effect.
"""

from __future__ import annotations

from ..config import Config, get_config
from ..detect.ensemble import PROMPT_VERSION as _DETECT_PV
from ..falsify.challenger import CRITIQUE_PROMPT_VERSION as _FALSIFY_CRITIQUE_PV
from ..falsify.challenger import PROMPT_VERSION as _FALSIFY_PV
from ..map.domain_map import PROMPT_VERSION as _MAP_PV
from ..normalize.adjudicate import PROMPT_VERSION as _NORMALIZE_PV
from ..store import db
from ..store.models import EvalRun

# The prompt version actually wired into each stage right now. Recorded on every run
# so a regression can be attributed to a specific prompt lineage. The falsify stage runs
# two prompts — the verdict prompt *and* the self-critique (reflect) prompt — so both are
# recorded (composite), matching the detect stage's multi-lens convention. Omitting the
# self-critique version would let a regression in the reflect step escape attribution.
STAGE_PROMPT_VERSIONS: dict[str, str] = {
    "map": _MAP_PV,
    "detect": _DETECT_PV,
    "falsify": f"{_FALSIFY_PV}+{_FALSIFY_CRITIQUE_PV}",
    "normalize": _NORMALIZE_PV,
}

# Tolerance so floating-point noise doesn't read as a regression.
_EPS = 1e-9


class RegressionError(RuntimeError):
    """Raised when a run's precision or recall regressed against the prior run."""


def record_and_check(
    *,
    lineage: str,
    precision: float,
    recall: float,
    prompt_versions: dict[str, str] | None = None,
    config: Config | None = None,
) -> EvalRun:
    """Persist this run's metrics and gate on regression vs. the prior run.

    Records the `EvalRun` unconditionally (so the regression is on the record), then
    raises `RegressionError` if precision or recall dropped against the immediately
    prior run for the same `lineage`. A first-ever run for a lineage cannot regress.
    """
    config = config or get_config()
    prior = db.last_eval_run(lineage, config)
    regressed = prior is not None and (
        precision < prior.precision - _EPS or recall < prior.recall - _EPS
    )

    run = EvalRun(
        lineage=lineage,
        prompt_versions=prompt_versions or dict(STAGE_PROMPT_VERSIONS),
        precision=precision,
        recall=recall,
        regressed_from_prior=regressed,
    )
    run.id = db.insert_eval_run(run, config)

    if regressed:
        raise RegressionError(
            f"eval regression on lineage '{lineage}': "
            f"prior precision={prior.precision:.3f} recall={prior.recall:.3f}; "
            f"new precision={precision:.3f} recall={recall:.3f}. "
            f"Prompt versions {run.prompt_versions} must not ship until this is resolved."
        )
    return run
