"""Deterministic, ground-truth-blind identities for review-acquisition funnels.

This module defines the OPT-029 contract without applying it to production acquisition.
Raw findings remain untouched; PR 2 will use these primitives to account for candidates
that are retained, deferred, or selected for a bounded human-review packet.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum


class ReviewPathClass(StrEnum):
    """Disclosed path classes used only to prioritize review effort."""

    PRODUCTION = "production"
    DEPLOYMENT = "deployment"
    CI = "ci"
    TEST = "test"
    DOCS_EXAMPLES = "docs_examples"
    VENDOR_GENERATED = "vendor_generated"


class ReviewPathTier(StrEnum):
    """Priority tiers; no tier predicts validity or changes stored findings."""

    PRIMARY = "tier_1_product_deployment"
    SUPPORTING = "tier_2_supporting"
    DEFERRED = "tier_3_vendor_generated"


@dataclass(frozen=True)
class AcquisitionIdentityInput:
    """Fields allowed to participate in OPT-029 identity decisions."""

    engagement: str
    producer: str
    rule_id: str
    file: str
    line_start: int
    line_end: int
    sink: str


@dataclass(frozen=True)
class AcquisitionFunnelCounts:
    """Monotonic counts disclosed by every OPT-029 acquisition plan."""

    raw: int
    after_pre_post_collapse: int
    after_exact_duplicate_collapse: int
    after_path_policy: int
    after_family_cap: int
    after_engagement_balance: int
    selected: int

    def __post_init__(self) -> None:
        values = (
            self.raw,
            self.after_pre_post_collapse,
            self.after_exact_duplicate_collapse,
            self.after_path_policy,
            self.after_family_cap,
            self.after_engagement_balance,
            self.selected,
        )
        if any(value < 0 for value in values):
            raise ValueError("acquisition funnel counts cannot be negative")
        if any(left < right for left, right in zip(values, values[1:])):
            raise ValueError("acquisition funnel counts must be monotonic")

    def deferred_by_stage(self) -> dict[str, int]:
        """Return every stage delta without implying finding invalidity."""
        return {
            "pre_post_collapse": self.raw - self.after_pre_post_collapse,
            "exact_duplicate_collapse": (
                self.after_pre_post_collapse
                - self.after_exact_duplicate_collapse
            ),
            "path_policy": (
                self.after_exact_duplicate_collapse - self.after_path_policy
            ),
            "family_cap": self.after_path_policy - self.after_family_cap,
            "engagement_balance": (
                self.after_family_cap - self.after_engagement_balance
            ),
            "packet_limit": self.after_engagement_balance - self.selected,
        }


_VENDOR_GENERATED_PARTS = {
    ".tox",
    ".venv",
    "build",
    "coverage",
    "dist",
    "generated",
    "node_modules",
    "third-party",
    "third_party",
    "vendor",
}
_DOCS_EXAMPLE_PARTS = {"doc", "docs", "example", "examples", "sample", "samples"}
_TEST_PARTS = {"spec", "test", "tests"}
_DEPLOYMENT_NAMES = {
    "compose.yaml",
    "compose.yml",
    "docker-compose.yaml",
    "docker-compose.yml",
    "dockerfile",
}
_DEPLOYMENT_SUFFIXES = (".cfg", ".ini", ".properties", ".toml", ".yaml", ".yml")


def normalize_acquisition_text(value: str) -> str:
    """Normalize identity text narrowly without semantic interpretation."""
    return " ".join(value.split())


def normalize_acquisition_path(value: str) -> str:
    """Normalize path separators and harmless leading/current-directory segments."""
    normalized = value.replace("\\", "/").strip()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return re.sub(r"/+", "/", normalized)


def classify_review_path(value: str) -> ReviewPathClass:
    """Classify a candidate path using the frozen OPT-029 taxonomy."""
    normalized = normalize_acquisition_path(value).casefold()
    parts = tuple(part for part in normalized.split("/") if part)
    name = parts[-1] if parts else ""
    directories = set(parts[:-1])
    if directories & _VENDOR_GENERATED_PARTS:
        return ReviewPathClass.VENDOR_GENERATED
    if normalized.startswith(".github/"):
        return ReviewPathClass.CI
    if (
        directories & _TEST_PARTS
        or any(part.endswith(("-test", "_test")) for part in directories)
        or name.endswith((".spec.js", ".spec.ts", "_test.py", "-test.js", "-test.ts"))
    ):
        return ReviewPathClass.TEST
    if (
        directories & _DOCS_EXAMPLE_PARTS
        or name.startswith(("changelog", "readme"))
    ):
        return ReviewPathClass.DOCS_EXAMPLES
    if (
        name in _DEPLOYMENT_NAMES
        or name.endswith(_DEPLOYMENT_SUFFIXES)
        or name.startswith(".yarnrc")
    ):
        return ReviewPathClass.DEPLOYMENT
    return ReviewPathClass.PRODUCTION


def review_path_tier(path_class: ReviewPathClass) -> ReviewPathTier:
    """Map a disclosed path class to its approved review priority tier."""
    if path_class in {ReviewPathClass.PRODUCTION, ReviewPathClass.DEPLOYMENT}:
        return ReviewPathTier.PRIMARY
    if path_class is ReviewPathClass.VENDOR_GENERATED:
        return ReviewPathTier.DEFERRED
    return ReviewPathTier.SUPPORTING


def exact_location_identity(candidate: AcquisitionIdentityInput) -> tuple[object, ...]:
    """Identity for exact duplicate collapse within one engagement."""
    return (
        candidate.engagement,
        normalize_acquisition_text(candidate.producer),
        normalize_acquisition_text(candidate.rule_id),
        normalize_acquisition_path(candidate.file),
        candidate.line_start,
        candidate.line_end,
        normalize_acquisition_text(candidate.sink),
    )


def pre_post_identity(candidate: AcquisitionIdentityInput) -> tuple[object, ...]:
    """Identity for unchanged evidence across a declared pre/post pair."""
    return exact_location_identity(candidate)[1:]


def repeated_family_identity(candidate: AcquisitionIdentityInput) -> tuple[str, ...]:
    """Approved family identity for the two-per-engagement review cap."""
    return (
        candidate.engagement,
        normalize_acquisition_text(candidate.producer),
        normalize_acquisition_text(candidate.rule_id),
        normalize_acquisition_text(candidate.sink),
    )
