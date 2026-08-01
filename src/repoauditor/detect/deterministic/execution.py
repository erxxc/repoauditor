"""Typed execution evidence shared by deterministic scanner adapters."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


ScannerStatus = Literal[
    "complete",
    "empty",
    "not-applicable",
    "partial",
    "unavailable",
    "failed",
    "disabled",
]

DETERMINISTIC_SCANNERS = (
    "semgrep",
    "semgrep-supplemental",
    "pip-audit",
    "osv-scanner",
    "gitleaks",
)


class ScannerExecution(BaseModel):
    """Evidence that distinguishes a clean zero from missing scanner coverage."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scanner: str
    status: ScannerStatus
    applicable: bool | None
    output_valid: bool
    finding_count: int = Field(ge=0)
    target_count: int = Field(ge=0)
    target_count_basis: Literal[
        "scanner-reported-files",
        "submitted-manifests",
        "submitted-root",
        "not-applicable",
        "unavailable",
        "disabled",
    ]
    version: str | None = None
    configuration: str | None = None
    invocation: tuple[str, ...] = ()
    configuration_digest: str | None = None
    rule_count: int | None = Field(default=None, ge=0)
    configuration_resolution: Literal[
        "pinned-verified",
        "embedded-default",
        "live-service",
        "not-applicable",
        "unavailable",
        "failed",
    ] | None = None
    advisory_database: str | None = None
    advisory_database_version: str | None = None
    advisory_database_checked_at: datetime | None = None
    failure_detail: str | None = None

    @model_validator(mode="after")
    def validate_status_evidence(self) -> "ScannerExecution":
        if self.status in {"complete", "empty"}:
            if self.applicable is not True or not self.output_valid or self.target_count < 1:
                raise ValueError(
                    "complete/empty scanner execution requires applicable validated output "
                    "and at least one target"
                )
        if self.status == "complete" and self.finding_count < 1:
            raise ValueError("complete scanner execution requires at least one finding")
        if self.status == "empty" and self.finding_count != 0:
            raise ValueError("empty scanner execution cannot contain findings")
        if self.status == "not-applicable" and (
            self.applicable is not False
            or self.target_count != 0
            or self.target_count_basis != "not-applicable"
        ):
            raise ValueError("not-applicable execution requires zero applicable targets")
        if self.status == "failed" and not self.failure_detail:
            raise ValueError("failed scanner execution requires failure detail")
        return self
