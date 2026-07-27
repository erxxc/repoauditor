"""Ground-truth-blind work planning for bounded live detection.

The planner qualifies the instrument before spending provider budget. It reports the
unbounded all-files × all-lenses workload, caps live regions through explicit operational
configuration, prioritizes independently produced scanner evidence and architecture-map
locations, and reserves stable content-derived coverage outside those signals. Fixture
answer keys, advisories, severities, and expected findings are never inputs.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

from ..config import Config
from ..map import ArchitectureMap
from ..sourcefiles import iter_source_files
if TYPE_CHECKING:
    from .ensemble import CandidateFinding


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

    sample_slots = min(config.detect.reserved_sample_regions, cap)
    indicated_slots = cap - sample_slots
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
    remaining = [
        (rel, path) for rel, path in by_rel.items() if rel not in selected_names
    ]
    remaining.sort(
        key=lambda item: hashlib.sha256(
            f"{commit}\0{item[0]}".encode()
        ).hexdigest()
    )
    for rel, path in remaining:
        if len(selected) >= cap:
            break
        selected.append(PlannedRegion(path, rel, "stable-coverage-sample"))
    return selected
