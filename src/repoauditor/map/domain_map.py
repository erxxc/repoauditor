"""Architecture-recovery stage.

The first LLM pass: a *schema-constrained extraction*, not free text. It reads the
ingested repo tree, hands the code to the model under
`prompts/architecture_recovery_v1.md`, and gets back structured
`TrustBoundary` / `EntryPoint` / `DataStore` / `Integration` data. The recovered
boundaries and entities are persisted through `store/` (the only DB owner), and the
returned map carries their ids so every downstream finding can foreign-key back to
the trust boundary it threatens.

This runs to completion before `detect/` — the whole pipeline is conditioned on it.
"""

from __future__ import annotations

from pathlib import Path

from ..config import Config, get_config
from ..llm import LLMClient, get_llm_client
from ..sourcefiles import iter_source_files, read_numbered
from ..store import db
from ..store.models import Entity, EntityKind, TrustBoundary as StoreTrustBoundary
from .schema import (
    ArchitectureExtraction,
    ArchitectureMap,
    EntryPoint,
    TrustBoundary,
)

PROMPT_VERSION = "architecture_recovery_v2"
PROMPT = (Path(__file__).parent / "prompts" / f"{PROMPT_VERSION}.md").read_text()

# Guardrails on how much source we feed the model. The first pass is chunked; a
# low-confidence extraction is re-passed with the fuller budget (per CLAUDE.md
# reliability layer: broader context before falling back to `unresolved`).
_MAX_FILES = 40
_CHUNK_CHARS = 60_000
_FULL_CHARS = 240_000


def _build_context(snapshot_path: Path, max_chars: int) -> str:
    """Concatenate the repo's source files (line-numbered) into one prompt body."""
    chunks: list[str] = []
    budget = max_chars
    for path in iter_source_files(snapshot_path)[:_MAX_FILES]:
        rel = path.relative_to(snapshot_path).as_posix()
        body = read_numbered(path)
        block = f"# FILE: {rel}\n{body}\n"
        if len(block) > budget:
            block = block[:budget]
        chunks.append(block)
        budget -= len(block)
        if budget <= 0:
            break
    return "\n".join(chunks)


def recover_architecture(
    snapshot_path: Path,
    repo_id: str,
    commit: str,
    config: Config | None = None,
    llm: LLMClient | None = None,
) -> ArchitectureMap:
    """Recover the architecture/trust-boundary map for an ingested snapshot.

    Extracts structured architecture from the code, persists boundaries + entities
    via `store/`, and returns an `ArchitectureMap` whose trust boundaries carry their
    persisted ids. Standalone and testable — inject a scripted `llm` in tests.
    """
    config = config or get_config()
    llm = llm or get_llm_client(config)
    snapshot_path = Path(snapshot_path)

    completion = llm.call(
        module="map",
        prompt_version=PROMPT_VERSION,
        system=PROMPT,
        user=_build_context(snapshot_path, _CHUNK_CHARS),
        schema=ArchitectureExtraction,
        context={"stage": "map", "repo_id": repo_id, "commit": commit},
    )

    # Low confidence: re-pass once with the full file content before accepting it.
    if completion.low_confidence:
        completion = llm.call(
            module="map",
            prompt_version=PROMPT_VERSION,
            system=PROMPT,
            user=_build_context(snapshot_path, _FULL_CHARS),
            schema=ArchitectureExtraction,
            context={"stage": "map", "repo_id": repo_id, "commit": commit, "repass": True},
        )

    extraction = completion.value
    # Still low after the re-pass -> record the entities as unresolved (not asserted
    # outright). Entities have no status column, so this rides in `metadata`.
    unresolved = completion.low_confidence
    entity_meta = (
        {"status": "unresolved", "confidence": completion.confidence} if unresolved else None
    )

    # Persist trust boundaries first so entities and findings can reference them.
    boundaries: list[TrustBoundary] = []
    name_to_id: dict[str, int] = {}
    for tb in extraction.trust_boundaries:
        tb_id = db.upsert_trust_boundary(
            StoreTrustBoundary(repo_id=repo_id, name=tb.name, description=tb.description),
            config,
        )
        name_to_id[tb.name] = tb_id
        boundaries.append(tb.model_copy(update={"id": tb_id}))

    # Persist entry points / data stores / integrations as entities, linked to a
    # boundary by name where the model provided one.
    def _persist(kind: EntityKind, name: str, location: str | None, boundary: str | None):
        db.upsert_entity(
            Entity(
                repo_id=repo_id,
                kind=kind,
                name=name,
                location=location,
                trust_boundary_id=name_to_id.get(boundary) if boundary else None,
                metadata=entity_meta,
            ),
            config,
        )

    for ep in extraction.entry_points:
        _persist(EntityKind.ENTRY_POINT, ep.name, ep.location, ep.trust_boundary)
    for ds in extraction.data_stores:
        _persist(EntityKind.DATA_STORE, ds.name, ds.location, None)
    for integ in extraction.integrations:
        _persist(EntityKind.INTEGRATION, integ.name, integ.location, None)

    return ArchitectureMap(
        repo_id=repo_id,
        commit=commit,
        trust_boundaries=boundaries,
        entry_points=extraction.entry_points,
        data_stores=extraction.data_stores,
        integrations=extraction.integrations,
    )


def load_architecture(repo_id: str, commit: str, config: Config | None = None) -> ArchitectureMap:
    """Reconstruct a repo's architecture map from the store (post-`map`).

    Lets `detect/` and `falsify/` run repo-level without re-running the LLM map pass:
    boundaries and entry-point entities are read back from `store/`, with ids intact.
    """
    config = config or get_config()
    boundaries = [
        TrustBoundary(id=tb.id, name=tb.name, description=tb.description)
        for tb in db.list_trust_boundaries(repo_id, config)
    ]
    entry_points = [
        EntryPoint(
            name=e.name,
            location=e.location,
            trust_boundary=_boundary_name(e.trust_boundary_id, boundaries),
        )
        for e in db.list_entities(repo_id, config)
        if e.kind is EntityKind.ENTRY_POINT
    ]
    return ArchitectureMap(
        repo_id=repo_id,
        commit=commit,
        trust_boundaries=boundaries,
        entry_points=entry_points,
    )


def _boundary_name(boundary_id: int | None, boundaries: list[TrustBoundary]) -> str | None:
    if boundary_id is None:
        return None
    for tb in boundaries:
        if tb.id == boundary_id:
            return tb.name
    return None
