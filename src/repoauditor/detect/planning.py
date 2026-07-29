"""Ground-truth-blind work planning for bounded live detection.

The planner qualifies the instrument before spending provider budget. It reports the
unbounded all-files × all-lenses workload, caps live regions through explicit operational
configuration, prioritizes independently produced scanner evidence and architecture-map
locations, and reserves stable path-derived, directory-stratified coverage outside those
signals. Path-only sampling keeps pre-fix/post-fix instruments comparable; it is not a
claim that a small blind sample covers every source file. Fixture
answer keys, advisories, severities, and expected findings are never inputs.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

from ..config import Config
from ..map import ArchitectureMap
from ..sourcefiles import iter_source_files, select_diverse_source_files
if TYPE_CHECKING:
    from .ensemble import CandidateFinding
    from .retrieval import RetrievalIndex


@dataclass(frozen=True)
class DetectionProjection:
    source_files: int
    lenses: int
    unbounded_base_calls: int
    planned_regions: int
    planned_base_calls: int
    omitted_regions: int


@dataclass(frozen=True)
class PlannedRegion:
    path: Path
    relative_path: str
    selection_basis: str


def validate_detection_projection(
    projection: DetectionProjection,
    config: Config,
    *,
    preceding_map_calls: int = 0,
) -> None:
    """Fail before paid detection when its minimum base calls cannot fit."""
    ceiling = config.llm.max_calls_per_pipeline_run
    minimum = preceding_map_calls + projection.planned_base_calls
    if ceiling and minimum > ceiling:
        raise ValueError(
            "bounded detection cannot fit the configured call ceiling: "
            f"minimum base calls={minimum} "
            f"(map reserve={preceding_map_calls}, detect={projection.planned_base_calls}), "
            f"ceiling={ceiling}; lower [detect].max_llm_regions_per_run"
        )


def project_detection_work(
    snapshot_path: Path, config: Config, *, lens_count: int
) -> DetectionProjection:
    source_files = len(iter_source_files(snapshot_path))
    planned = min(source_files, config.detect.max_llm_regions_per_run)
    return DetectionProjection(
        source_files=source_files,
        lenses=lens_count,
        unbounded_base_calls=source_files * lens_count,
        planned_regions=planned,
        planned_base_calls=planned * lens_count,
        omitted_regions=source_files - planned,
    )


def _location_file(location: str | None) -> str | None:
    if not location:
        return None
    candidate = location.split(":", 1)[0].replace("\\", "/").lstrip("./")
    return candidate or None


def plan_detection_regions(
    snapshot_path: Path,
    config: Config,
    *,
    commit: str,
    architecture: ArchitectureMap,
    tool_candidates: Iterable["CandidateFinding"],
    index: "RetrievalIndex | None" = None,
) -> list[PlannedRegion]:
    """Select bounded regions without consulting vulnerability ground truth."""
    files = iter_source_files(snapshot_path)
    cap = config.detect.max_llm_regions_per_run
    if cap == 0 or not files:
        return []
    by_rel = {
        path.relative_to(snapshot_path).as_posix(): path for path in files
    }
    indicated: dict[str, str] = {}
    for candidate in tool_candidates:
        rel = candidate.file.replace("\\", "/").lstrip("./")
        if rel in by_rel:
            indicated.setdefault(rel, f"deterministic:{candidate.producer or candidate.source_tool}")
    for entity in (
        *architecture.entry_points,
        *architecture.data_stores,
        *architecture.integrations,
    ):
        rel = _location_file(entity.location)
        if rel in by_rel:
            indicated.setdefault(rel, "architecture-map")

    neighbors = _architecture_neighbors(
        architecture,
        by_rel,
        index,
    )
    sample_slots = min(config.detect.reserved_sample_regions, cap)
    evidence_slots = cap - sample_slots
    neighbor_slots = min(
        config.detect.reserved_architecture_neighbor_regions,
        evidence_slots,
        len(neighbors),
    )
    indicated_slots = evidence_slots - neighbor_slots
    priority = {"deterministic": 0, "architecture-map": 1}
    ordered_indicated = sorted(
        indicated.items(),
        key=lambda item: (
            priority.get(item[1].split(":", 1)[0], 2),
            item[0],
        ),
    )
    selected: list[PlannedRegion] = [
        PlannedRegion(by_rel[rel], rel, basis)
        for rel, basis in ordered_indicated[:indicated_slots]
    ]
    selected_names = {item.relative_path for item in selected}
    selected_neighbors = 0
    for rel, basis in neighbors:
        if selected_neighbors >= neighbor_slots:
            break
        if rel in selected_names:
            continue
        selected.append(PlannedRegion(by_rel[rel], rel, basis))
        selected_names.add(rel)
        selected_neighbors += 1
    # Return unused neighbor capacity to direct evidence before generic sampling.
    for rel, basis in ordered_indicated[indicated_slots:]:
        if len(selected) >= evidence_slots:
            break
        if rel not in selected_names:
            selected.append(PlannedRegion(by_rel[rel], rel, basis))
            selected_names.add(rel)
    # Path-only ordering keeps the instrument comparable across pre/post commits.
    # Directory stratification and a bounded test share avoid alphabetical/root and
    # test-suite dominance without consulting advisories or expected findings.
    remaining = [
        path
        for path in select_diverse_source_files(snapshot_path, len(files))
        if path.relative_to(snapshot_path).as_posix() not in selected_names
    ]
    for path in remaining:
        if len(selected) >= cap:
            break
        rel = path.relative_to(snapshot_path).as_posix()
        selected.append(PlannedRegion(path, rel, "stable-coverage-sample"))
    return selected


def _architecture_neighbors(
    architecture: ArchitectureMap,
    by_rel: dict[str, Path],
    index: "RetrievalIndex | None",
) -> list[tuple[str, str]]:
    """Return path-blind syntactic neighbors of exact architecture-map locations."""
    if index is None:
        return []
    seeds = sorted({
        rel
        for entity in (
            *architecture.entry_points,
            *architecture.data_stores,
            *architecture.integrations,
        )
        if (rel := _location_file(entity.location)) in by_rel
    })
    candidates: list[tuple[int, str, str, int, str]] = []
    for seed in seeds:
        definitions = index.functions_in_file(seed)
        symbols = sorted({definition.symbol for definition in definitions})
        for caller, _matched in index.find_callers_matching(symbols):
            if caller.file != seed and caller.file in by_rel:
                candidates.append((
                    0,
                    seed,
                    caller.file,
                    caller.line_start,
                    "architecture-neighbor:call-name-match",
                ))
        for symbol in symbols:
            for callee in index.find_callees(symbol):
                if callee.file != seed and callee.file in by_rel:
                    candidates.append((
                        1,
                        seed,
                        callee.file,
                        callee.line_start,
                        "architecture-neighbor:callee-definition",
                    ))
    ordered: dict[str, str] = {}
    for _relation, _seed, rel, _line, basis in sorted(candidates):
        ordered.setdefault(rel, basis)
    return list(ordered.items())
