"""Closed-loop eval: persist each golden-harness run and gate on regressions."""

from .regression import (
    STAGE_PROMPT_VERSIONS,
    RegressionError,
    record_and_check,
)
from .convergence import (
    ConvergenceResult,
    evaluate_finding_convergence,
    render_convergence,
    run_finding_convergence,
)
from .sentinels import (
    SentinelQualification,
    evaluate_manufactured_sentinels,
    render_sentinel_qualification,
)
from .usage_calibration import (
    UsageCalibrationReport,
    build_usage_calibration,
    render_usage_calibration,
)

__all__ = [
    "record_and_check",
    "RegressionError",
    "STAGE_PROMPT_VERSIONS",
    "ConvergenceResult",
    "evaluate_finding_convergence",
    "run_finding_convergence",
    "render_convergence",
    "SentinelQualification",
    "evaluate_manufactured_sentinels",
    "render_sentinel_qualification",
    "UsageCalibrationReport",
    "build_usage_calibration",
    "render_usage_calibration",
]
