"""Structured security claims and narrowly scoped deterministic verification."""

from __future__ import annotations

from ..store.models import (
    ClaimEvidence,
    ClaimVerification,
    ClaimVerificationStatus,
    SecurityClaim,
)
from .slicing import PythonSliceEvidence, SLICE_VERSION

CLAIM_VERSION = "security_claim_v1"
VERIFIER_NAME = "python-local-structural"
VERIFIER_VERSION = "python_local_structural_v1"


def _evidence(file: str, item) -> ClaimEvidence:
    return ClaimEvidence(file=file, line=item.line, source=item.source)


def claim_from_slice(
    finding_id: int, evidence: PythonSliceEvidence
) -> SecurityClaim:
    """Translate deterministic slice facts into a persisted, checkable claim."""
    sources = [_evidence(evidence.file, item) for item in evidence.source_evidence]
    assignments = [_evidence(evidence.file, item) for item in evidence.assignments]
    sink = _evidence(evidence.file, evidence.sink) if evidence.sink else None
    controls = [
        _evidence(evidence.file, item) for item in evidence.sanitizer_candidates
    ]
    return SecurityClaim(
        finding_id=finding_id,
        claim_version=CLAIM_VERSION,
        mechanism=evidence.mechanism,
        source_evidence=sources,
        sink_evidence=sink,
        path_nodes=[*sources, *assignments, *([sink] if sink else [])],
        path_predicates=[],
        control_candidate=controls[0] if controls else None,
        producer_type="deterministic",
        producer_name=SLICE_VERSION,
    )


def verify_structural_claim(
    claim: SecurityClaim, evidence: PythonSliceEvidence
) -> ClaimVerification:
    """Verify local structural facts only, never exploitability or reachability."""
    checks = {
        "supported_python_slice": True,
        "sink_present": claim.sink_evidence is not None,
        "source_present": bool(claim.source_evidence),
        "local_chain_present": bool(claim.path_nodes),
        "slice_dependencies_complete": evidence.status == "local",
    }
    if evidence.status != "local" or not all(
        checks[name] for name in ("sink_present", "source_present", "local_chain_present")
    ):
        status = ClaimVerificationStatus.INCOMPLETE
        reason = (
            "Structural verification incomplete: "
            + "; ".join(evidence.limitations or ["required local evidence is missing"])
        )
    else:
        status = ClaimVerificationStatus.VERIFIED
        reason = (
            "Verified only that the bounded Python slice contains a local source, assignment "
            "chain, and supported sink. End-to-end reachability, attacker control, path "
            "feasibility, control effectiveness, and exploitability remain unverified."
        )
    return ClaimVerification(
        claim_id=claim.id or 0,
        status=status,
        verifier_name=VERIFIER_NAME,
        verifier_version=VERIFIER_VERSION,
        checks=checks,
        reason=reason,
    )
