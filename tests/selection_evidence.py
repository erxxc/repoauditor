"""Ground-truth-blind evidence helpers for production-region selection evaluation.

Capture is deliberately separate from target adjudication. The capture function has no
answer-key or target argument and records only the inputs available to the production
planner: source paths, architecture-map locations, deterministic candidates, and bounded
configuration. A later reviewer may compare an already-written capture with a human-
reviewed advisory target. This is evaluation infrastructure, not production planning logic.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from repoauditor.config import Config
from repoauditor.detect.ensemble import CandidateFinding
from repoauditor.detect.planning import plan_detection_regions
from repoauditor.map import ArchitectureMap
from repoauditor.sourcefiles import iter_source_files


def snapshot_digest(snapshot_path: Path) -> str:
    """Hash all non-git snapshot paths and bytes without consulting an answer key."""
    digest = hashlib.sha256()
    for path in sorted(item for item in snapshot_path.rglob("*") if item.is_file()):
        relative = path.relative_to(snapshot_path).as_posix()
        if ".git" in Path(relative).parts:
            continue
        digest.update(relative.encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def capture_production_selection(
    snapshot_path: Path,
    *,
    repo_id: str,
    commit: str,
    architecture: ArchitectureMap,
    tool_candidates: list[CandidateFinding],
    config: Config,
) -> dict:
    """Capture the real planner output without accepting target metadata."""
    snapshot_path = Path(snapshot_path)
    if architecture.repo_id != repo_id or architecture.commit != commit:
        raise ValueError("architecture identity differs from selection capture")
    regions = plan_detection_regions(
        snapshot_path,
        config,
        commit=commit,
        architecture=architecture,
        tool_candidates=tool_candidates,
    )
    source_paths = [
        path.relative_to(snapshot_path).as_posix()
        for path in iter_source_files(snapshot_path)
    ]
    selected_paths = [region.relative_path for region in regions]
    selected_set = set(selected_paths)
    capture = {
        "schema_version": "production-selection-capture-v1",
        "repo_id": repo_id,
        "commit": commit,
        "snapshot_digest": snapshot_digest(snapshot_path),
        "instrument": {
            "max_llm_regions_per_run": config.detect.max_llm_regions_per_run,
            "reserved_sample_regions": config.detect.reserved_sample_regions,
            "reserved_architecture_neighbor_regions": (
                config.detect.reserved_architecture_neighbor_regions
            ),
            "architecture_entry_points": len(architecture.entry_points),
            "architecture_data_stores": len(architecture.data_stores),
            "architecture_integrations": len(architecture.integrations),
            "deterministic_candidate_count": len(tool_candidates),
        },
        "source_file_count": len(source_paths),
        "selected_count": len(selected_paths),
        "omitted_count": len(source_paths) - len(selected_paths),
        "selected_regions": [
            {
                "path": region.relative_path,
                "selection_basis": region.selection_basis,
            }
            for region in regions
        ],
        "omitted_regions": [
            path for path in source_paths if path not in selected_set
        ],
        "target_metadata_consulted": False,
    }
    canonical = json.dumps(capture, sort_keys=True, separators=(",", ":")).encode()
    return {**capture, "capture_sha256": hashlib.sha256(canonical).hexdigest()}


def adjudicate_target_selection(
    capture: dict,
    snapshot_path: Path,
    *,
    target_file: str,
) -> dict:
    """Reveal one reviewed target only after its selection capture is immutable."""
    expected_hash = capture.get("capture_sha256")
    unsigned = {
        key: value for key, value in capture.items() if key != "capture_sha256"
    }
    actual_hash = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if not expected_hash or actual_hash != expected_hash:
        raise ValueError("production-selection capture integrity check failed")
    selected_paths = [
        region["path"] for region in capture.get("selected_regions", [])
    ]
    omitted_paths = capture.get("omitted_regions", [])
    if (
        len(selected_paths) != capture.get("selected_count")
        or len(omitted_paths) != capture.get("omitted_count")
        or len(selected_paths) + len(omitted_paths)
        != capture.get("source_file_count")
        or len(set(selected_paths)) != len(selected_paths)
        or len(set(omitted_paths)) != len(omitted_paths)
        or set(selected_paths) & set(omitted_paths)
    ):
        raise ValueError("production-selection capture does not close")
    if snapshot_digest(Path(snapshot_path)) != capture["snapshot_digest"]:
        raise ValueError("snapshot differs from the frozen selection capture")
    normalized_target = target_file.replace("\\", "/").lstrip("./")
    if not (Path(snapshot_path) / normalized_target).is_file():
        raise ValueError("reviewed target is absent from the frozen snapshot")
    selected = {
        region["path"]: region["selection_basis"]
        for region in capture["selected_regions"]
    }
    source_inventory = selected.keys() | set(capture["omitted_regions"])
    target_in_source_inventory = normalized_target in source_inventory
    return {
        "schema_version": "production-selection-adjudication-v1",
        "capture_sha256": expected_hash,
        "target_file": normalized_target,
        "target_in_source_inventory": target_in_source_inventory,
        "target_selected": normalized_target in selected,
        "selection_basis": selected.get(normalized_target),
        "omission_basis": (
            None
            if normalized_target in selected
            else (
                "bounded_plan_omission"
                if target_in_source_inventory
                else "outside_source_inventory"
            )
        ),
        "interpretation": (
            "Planner selection evidence only; an omitted target is not a semantic "
            "detector false negative, and a selected target is not a recovered finding."
        ),
    }


def adjudicate_pair_selection(
    pre_capture: dict,
    post_capture: dict,
    pre_snapshot: Path,
    post_snapshot: Path,
    *,
    target_file: str,
) -> dict:
    """Reveal one target after both comparable variant captures already exist."""
    config_fields = (
        "max_llm_regions_per_run",
        "reserved_sample_regions",
        "reserved_architecture_neighbor_regions",
    )
    pre_instrument = pre_capture.get("instrument", {})
    post_instrument = post_capture.get("instrument", {})
    if any(
        pre_instrument.get(field) != post_instrument.get(field)
        for field in config_fields
    ):
        raise ValueError("pre-fix/post-fix production-selection config differs")
    return {
        "schema_version": "production-selection-pair-adjudication-v1",
        "target_disclosed_after_both_captures": True,
        "pre_fix": adjudicate_target_selection(
            pre_capture, pre_snapshot, target_file=target_file
        ),
        "post_fix": adjudicate_target_selection(
            post_capture, post_snapshot, target_file=target_file
        ),
        "interpretation": (
            "Pre/post planner coverage comparison only; no semantic detection or "
            "vulnerability-recovery claim."
        ),
    }
