"""Architecture-map schema (map-stage output).

Pydantic stubs for the structured domain map recovered *before* any vulnerability
hunting. These types describe the target's shape — where trust changes, what the
entry points are, where data rests, and what it talks to — so that every downstream
finding can be tied back to a trust boundary.

Stub only: fields are intentionally minimal and will grow as the map stage lands.
The persisted forms live in `store/models.py` (`TrustBoundary`, `Entity`).
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class TrustBoundary(BaseModel):
    """A boundary across which trust level changes (network edge, authz gate, ...)."""

    name: str
    description: str | None = None
    # Populated after the boundary is persisted, so findings can foreign-key to it.
    id: int | None = None


class EntryPoint(BaseModel):
    """An externally reachable way into the system (HTTP route, CLI, queue consumer)."""

    name: str
    location: str | None = None  # file:line or symbol
    trust_boundary: str | None = None  # name of the crossing TrustBoundary


class DataStore(BaseModel):
    """Where data rests (database, cache, bucket, file, secret store)."""

    name: str
    kind: str | None = None  # e.g. "postgres", "s3", "redis"
    location: str | None = None


class Integration(BaseModel):
    """An external system the target depends on or talks to."""

    name: str
    direction: str | None = None  # "inbound" | "outbound" | "bidirectional"
    location: str | None = None


class ArchitectureExtraction(BaseModel):
    """Exactly what the architecture-recovery model is asked to output.

    Deliberately excludes `repo_id` / `commit` (the pipeline knows those) so the
    model's whole job is structured extraction of the architecture itself — this is
    the schema handed to structured outputs, not free prose.
    """

    trust_boundaries: list[TrustBoundary] = Field(default_factory=list)
    entry_points: list[EntryPoint] = Field(default_factory=list)
    data_stores: list[DataStore] = Field(default_factory=list)
    integrations: list[Integration] = Field(default_factory=list)
    # The model's own confidence in this extraction (architecture_recovery_v2+).
    # Below the configured threshold, map re-passes with full file content.
    confidence: float = 1.0


class ArchitectureMap(BaseModel):
    """Aggregate map for one ingested repo — the output of the map stage.

    Carries the persisted trust-boundary ids so downstream findings can foreign-key
    back to the boundary they threaten.
    """

    repo_id: str
    commit: str
    trust_boundaries: list[TrustBoundary] = Field(default_factory=list)
    entry_points: list[EntryPoint] = Field(default_factory=list)
    data_stores: list[DataStore] = Field(default_factory=list)
    integrations: list[Integration] = Field(default_factory=list)

    def trust_boundary_id(self, name: str | None) -> int | None:
        """Persisted id of the boundary called `name`, or the first boundary's id.

        Every finding must trace back to a trust boundary; when a candidate names one
        we resolve it, otherwise we fall back to the primary boundary so the
        foreign-key link is never null.
        """
        if name is not None:
            for tb in self.trust_boundaries:
                if tb.name == name and tb.id is not None:
                    return tb.id
        for tb in self.trust_boundaries:
            if tb.id is not None:
                return tb.id
        return None


class EntityKind(StrEnum):
    """Discriminator mirroring `store.models.EntityKind` for map->store persistence."""

    ENTRY_POINT = "entry_point"
    DATA_STORE = "data_store"
    INTEGRATION = "integration"
    COMPONENT = "component"
