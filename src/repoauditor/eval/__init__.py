"""Closed-loop eval: persist each golden-harness run and gate on regressions."""

from .regression import (
    STAGE_PROMPT_VERSIONS,
    RegressionError,
    record_and_check,
)

__all__ = ["record_and_check", "RegressionError", "STAGE_PROMPT_VERSIONS"]
