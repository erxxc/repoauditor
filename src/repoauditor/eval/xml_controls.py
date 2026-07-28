"""Deterministic manufactured controls for XML security-decision consistency.

This checker answers one narrow structural question declared by an external answer key:
does security validation use one parsed XML representation while protected data is consumed
from another, or is data consumed from the exact verified representation? It does not parse
Ruby, prove that two real parsers disagree for an exploit document, establish attacker
control, validate a signature, or prove an authentication bypass.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel


class XMLRepresentationStatus(StrEnum):
    DISTINCT_VALIDATED_AND_CONSUMED = "distinct_validated_and_consumed"
    VERIFIED_REPRESENTATION_CONSUMED = "verified_representation_consumed"
    VERIFICATION_INCOMPLETE = "verification_incomplete"


class XMLRepresentationWitness(BaseModel):
    validated_representation: str
    consumed_representation: str
    consumed_from_verified_node: bool


class XMLRepresentationVerification(BaseModel):
    status: XMLRepresentationStatus
    validated_representation: str
    consumed_representation: str
    reason: str


def verify_xml_representation_witness(
    witness: XMLRepresentationWitness,
) -> XMLRepresentationVerification:
    """Compare declared validation and consumption representations without code inference."""
    validated = witness.validated_representation.strip()
    consumed = witness.consumed_representation.strip()
    if not validated or not consumed:
        return XMLRepresentationVerification(
            status=XMLRepresentationStatus.VERIFICATION_INCOMPLETE,
            validated_representation=validated,
            consumed_representation=consumed,
            reason="Both manufactured representation identifiers are required.",
        )
    if witness.consumed_from_verified_node and validated == consumed:
        return XMLRepresentationVerification(
            status=XMLRepresentationStatus.VERIFIED_REPRESENTATION_CONSUMED,
            validated_representation=validated,
            consumed_representation=consumed,
            reason=(
                "The external answer key declares that protected data is consumed from "
                "the same representation returned by signature verification."
            ),
        )
    if not witness.consumed_from_verified_node and validated != consumed:
        return XMLRepresentationVerification(
            status=XMLRepresentationStatus.DISTINCT_VALIDATED_AND_CONSUMED,
            validated_representation=validated,
            consumed_representation=consumed,
            reason=(
                "The external answer key declares distinct representations for the "
                "security decision and protected-data consumption."
            ),
        )
    return XMLRepresentationVerification(
        status=XMLRepresentationStatus.VERIFICATION_INCOMPLETE,
        validated_representation=validated,
        consumed_representation=consumed,
        reason=(
            "The declarations do not establish either a distinct-representation hazard "
            "or same-verified-representation control."
        ),
    )
