"""Deterministic manufactured controls for archive-entry containment.

This checker answers one narrow question: does a concrete archive entry resolve outside a
declared destination, and would the declared containment policy accept or reject it? It
does not parse application source, establish that the entry is attacker-controlled, or
prove that a filesystem sink executes.
"""

from __future__ import annotations

import posixpath
from enum import StrEnum

from pydantic import BaseModel


class ArchiveWitnessStatus(StrEnum):
    VERIFIED_ESCAPE_ACCEPTED = "verified_escape_accepted"
    VERIFIED_ESCAPE_REJECTED = "verified_escape_rejected"
    NOT_AN_ESCAPE = "not_an_escape"
    VERIFICATION_INCOMPLETE = "verification_incomplete"


class ArchivePathWitness(BaseModel):
    """Concrete entry and declared containment behavior for one manufactured case."""

    destination: str
    entry_name: str
    containment_enforced: bool


class ArchiveWitnessVerification(BaseModel):
    status: ArchiveWitnessStatus
    destination: str
    entry_name: str
    resolved_path: str | None = None
    escapes_destination: bool | None = None
    accepted: bool | None = None
    reason: str


def verify_archive_path_witness(
    witness: ArchivePathWitness,
) -> ArchiveWitnessVerification:
    """Resolve a POSIX archive entry lexically and apply the declared containment policy."""
    destination = posixpath.normpath(witness.destination)
    if not destination.startswith("/"):
        return ArchiveWitnessVerification(
            status=ArchiveWitnessStatus.VERIFICATION_INCOMPLETE,
            destination=witness.destination,
            entry_name=witness.entry_name,
            reason="The manufactured destination must be an absolute POSIX path.",
        )
    if witness.entry_name.startswith("/"):
        resolved = posixpath.normpath(witness.entry_name)
    else:
        resolved = posixpath.normpath(posixpath.join(destination, witness.entry_name))
    try:
        escapes = posixpath.commonpath([destination, resolved]) != destination
    except ValueError:
        return ArchiveWitnessVerification(
            status=ArchiveWitnessStatus.VERIFICATION_INCOMPLETE,
            destination=destination,
            entry_name=witness.entry_name,
            resolved_path=resolved,
            reason="The destination and resolved entry could not be compared.",
        )
    if not escapes:
        return ArchiveWitnessVerification(
            status=ArchiveWitnessStatus.NOT_AN_ESCAPE,
            destination=destination,
            entry_name=witness.entry_name,
            resolved_path=resolved,
            escapes_destination=False,
            accepted=True,
            reason="The concrete archive entry remains within the destination.",
        )
    if witness.containment_enforced:
        return ArchiveWitnessVerification(
            status=ArchiveWitnessStatus.VERIFIED_ESCAPE_REJECTED,
            destination=destination,
            entry_name=witness.entry_name,
            resolved_path=resolved,
            escapes_destination=True,
            accepted=False,
            reason=(
                "The entry resolves outside the destination and the declared normalized "
                "containment policy rejects it."
            ),
        )
    return ArchiveWitnessVerification(
        status=ArchiveWitnessStatus.VERIFIED_ESCAPE_ACCEPTED,
        destination=destination,
        entry_name=witness.entry_name,
        resolved_path=resolved,
        escapes_destination=True,
        accepted=True,
        reason=(
            "The entry resolves outside the destination and no containment policy is "
            "declared. Source provenance and sink execution remain unverified."
        ),
    )
