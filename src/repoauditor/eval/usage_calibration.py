"""Offline comparison of paid-run usage against configured circuit breakers.

This module never calls a provider and never recommends or changes a limit. It reads three
explicitly selected pipeline runs (one purpose-built lightweight calibration run and one
independent pre/post pair), preserves unknown provider usage as a blocker, and reports the
observed utilization of the currently configured operational ceilings. The analyst decides
whether later evidence justifies a configuration change.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from ..config import Config, get_config
from ..store import db
from ..store.models import RunStatus

CalibrationRole = Literal["lightweight", "independent_pre", "independent_post"]
_REQUIRED_ROLES: tuple[CalibrationRole, ...] = (
    "lightweight", "independent_pre", "independent_post",
)
_SOURCE_MARKERS: dict[CalibrationRole, str] = {
    "lightweight": "uat_lightweight_app",
    "independent_pre": "independent_serialize_javascript_pre",
    "independent_post": "independent_serialize_javascript_post",
}


class UsageObservation(BaseModel):
    role: CalibrationRole
    run_id: int
    source: str
    status: str
    calls: int
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    processed_tokens: int
    unknown_usage_calls: int
    provider_latency_ms: int
    call_limit: int
    token_limit: int
    call_utilization: float | None
    token_utilization: float | None


class UsageCalibrationReport(BaseModel):
    """Evidence sufficiency and observed utilization; never an automatic recommendation."""

    ready: bool
    blockers: list[str] = Field(default_factory=list)
    observations: list[UsageObservation]
    peak_call_utilization: float | None
    peak_token_utilization: float | None
    methodology: str = (
        "Descriptive comparison of one lightweight run and one independent pre/post pair "
        "against current operational ceilings. Unknown provider token metadata blocks "
        "token calibration. No optimal or recommended limit is inferred."
    )


def build_usage_calibration(
    run_ids: dict[CalibrationRole, int],
    config: Config | None = None,
) -> UsageCalibrationReport:
    """Build a fail-closed calibration report from already-recorded pipeline runs."""
    config = config or get_config()
    blockers: list[str] = []
    observations: list[UsageObservation] = []
    selected_ids = [run_id for run_id in run_ids.values() if run_id is not None]
    if len(selected_ids) != len(set(selected_ids)):
        blockers.append("each calibration role must use a distinct pipeline run")
    for role in _REQUIRED_ROLES:
        run_id = run_ids.get(role)
        if run_id is None:
            blockers.append(f"missing required role: {role}")
            continue
        run = db.get_pipeline_run(run_id, config)
        if run is None:
            blockers.append(f"{role}: pipeline run #{run_id} not found")
            continue
        totals = db.summarize_model_usage(run_id, config)
        processed = (
            totals["input_tokens"] + totals["output_tokens"]
            + totals["cache_read_tokens"] + totals["cache_write_tokens"]
        )
        call_limit = config.llm.max_calls_per_pipeline_run
        token_limit = config.llm.max_tokens_per_pipeline_run
        observations.append(UsageObservation(
            role=role,
            run_id=run_id,
            source=run.source,
            status=run.status.value,
            calls=totals["calls"],
            input_tokens=totals["input_tokens"],
            output_tokens=totals["output_tokens"],
            cache_read_tokens=totals["cache_read_tokens"],
            cache_write_tokens=totals["cache_write_tokens"],
            processed_tokens=processed,
            unknown_usage_calls=totals["unknown_usage_calls"],
            provider_latency_ms=totals["latency_ms"],
            call_limit=call_limit,
            token_limit=token_limit,
            call_utilization=(totals["calls"] / call_limit if call_limit else None),
            token_utilization=(processed / token_limit if token_limit else None),
        ))
        if run.status is not RunStatus.COMPLETED:
            blockers.append(f"{role}: run #{run_id} status is {run.status.value}")
        if _SOURCE_MARKERS[role] not in run.source:
            blockers.append(
                f"{role}: run #{run_id} source does not identify "
                f"{_SOURCE_MARKERS[role]}"
            )
        if totals["calls"] == 0:
            blockers.append(f"{role}: run #{run_id} has no recorded provider calls")
        if totals["unknown_usage_calls"]:
            blockers.append(
                f"{role}: run #{run_id} has {totals['unknown_usage_calls']} "
                "call(s) without token metadata"
            )

    call_values = [
        item.call_utilization for item in observations
        if item.call_utilization is not None
    ]
    token_values = [
        item.token_utilization for item in observations
        if item.token_utilization is not None
    ]
    return UsageCalibrationReport(
        ready=not blockers and len(observations) == len(_REQUIRED_ROLES),
        blockers=blockers,
        observations=observations,
        peak_call_utilization=max(call_values, default=None),
        peak_token_utilization=max(token_values, default=None),
    )


def render_usage_calibration(report: UsageCalibrationReport) -> str:
    """Render a compact analyst-facing, non-prescriptive calibration summary."""
    lines = [
        "LLM usage calibration — " + ("ready" if report.ready else "not ready"),
        report.methodology,
    ]
    for item in report.observations:
        call_util = (
            f"{item.call_utilization:.1%}" if item.call_utilization is not None else "disabled"
        )
        token_util = (
            f"{item.token_utilization:.1%}" if item.token_utilization is not None else "disabled"
        )
        lines.append(
            f"{item.role}: run #{item.run_id}; status={item.status}; calls={item.calls} "
            f"({call_util}); processed-tokens={item.processed_tokens} ({token_util}); "
            f"unknown-usage-calls={item.unknown_usage_calls}; "
            f"provider-latency={item.provider_latency_ms}ms"
        )
    if report.blockers:
        lines.append("blockers:")
        lines.extend(f"- {blocker}" for blocker in report.blockers)
    lines.append("No limit change is recommended automatically; an analyst reviews the evidence.")
    return "\n".join(lines)
