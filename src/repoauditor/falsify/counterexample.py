"""Small deterministic checker for concrete JavaScript regex-guard witnesses.

The checker proves only whether a supplied string matches the cited regex literal. It does
not prove that the application accepts the string, that the guarded operation is dangerous,
or that the path executes. Those remain separate evidence obligations.
"""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel


class WitnessVerificationStatus(StrEnum):
    VERIFIED_GUARD_MISS = "verified_guard_miss"
    REFUTED_GUARD_MATCH = "refuted_guard_match"
    VERIFICATION_INCOMPLETE = "verification_incomplete"


class RegexGuardWitness(BaseModel):
    """A concrete input asserted to evade one cited JavaScript regex guard."""

    input: str
    control_expression: str
    expected_security_effect: str


class WitnessVerification(BaseModel):
    """Result of checking only the regex-match portion of a bypass claim."""

    status: WitnessVerificationStatus
    pattern: str | None = None
    flags: str | None = None
    input: str
    guard_matched: bool | None = None
    reason: str


_JS_TEST_RE = re.compile(
    r"/(?P<pattern>(?:\\.|[^/\n])*)/(?P<flags>[a-z]*)\.test\s*\("
)
_SUPPORTED_FLAGS = {"i", "m", "s"}


def verify_javascript_regex_guard_witness(
    witness: RegexGuardWitness,
) -> WitnessVerification:
    """Check whether the witness makes a supported ``/regex/flags.test(...)`` miss."""
    parsed = _JS_TEST_RE.search(witness.control_expression)
    if parsed is None:
        return WitnessVerification(
            status=WitnessVerificationStatus.VERIFICATION_INCOMPLETE,
            input=witness.input,
            reason="No JavaScript regex .test(...) expression was found.",
        )
    pattern = parsed.group("pattern")
    flags_text = parsed.group("flags")
    unsupported = set(flags_text) - _SUPPORTED_FLAGS
    if unsupported:
        return WitnessVerification(
            status=WitnessVerificationStatus.VERIFICATION_INCOMPLETE,
            pattern=pattern,
            flags=flags_text,
            input=witness.input,
            reason="Unsupported JavaScript regex flags: " + "".join(sorted(unsupported)),
        )
    flags = 0
    if "i" in flags_text:
        flags |= re.IGNORECASE
    if "m" in flags_text:
        flags |= re.MULTILINE
    if "s" in flags_text:
        flags |= re.DOTALL
    try:
        matched = re.search(pattern, witness.input, flags) is not None
    except re.error as exc:
        return WitnessVerification(
            status=WitnessVerificationStatus.VERIFICATION_INCOMPLETE,
            pattern=pattern,
            flags=flags_text,
            input=witness.input,
            reason=f"Regex dialect could not be checked safely: {exc}",
        )
    if matched:
        return WitnessVerification(
            status=WitnessVerificationStatus.REFUTED_GUARD_MATCH,
            pattern=pattern,
            flags=flags_text,
            input=witness.input,
            guard_matched=True,
            reason="The cited regex matches the proposed input; this is not a guard miss.",
        )
    return WitnessVerification(
        status=WitnessVerificationStatus.VERIFIED_GUARD_MISS,
        pattern=pattern,
        flags=flags_text,
        input=witness.input,
        guard_matched=False,
        reason=(
            "The cited regex does not match the proposed input. Application acceptance, "
            "path feasibility, and security effect remain unverified."
        ),
    )
