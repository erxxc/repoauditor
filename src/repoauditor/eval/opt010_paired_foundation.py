"""Evaluation-only paired-runner contracts for OPT-010 G03b/G04 qualification.

This module has no provider, store, scanner, subprocess, or production-pipeline entry
point.  It validates scripted synthetic arm observations, computes the frozen paired
metrics, and constructs the already-qualified read-only facade only from caller-supplied
in-memory objects.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable

from ..config import AgentReadOnlyToolsConfig
from ..detect.retrieval import RetrievalIndex
from ..falsify.read_only_tools import AgentReadOnlyTools
from ..map import ArchitectureMap
from ..store.models import Finding


PROTOCOL_VERSION = "opt010-g03b-g04-paired-evaluation-v1"
PROMPT_VERSION = "opt010_agent_qualification_v1"
ARMS = ("baseline", "agent")
SUPPORTED_CELLS = {
    "Python": frozenset({"sql_injection", "command_injection", "ssrf"}),
    "TypeScript": frozenset({"command_injection", "ssrf"}),
    "Java": frozenset({"ssrf"}),
    "Ruby": frozenset({"unsafe_deserialization"}),
}
UNSUPPORTED_LANGUAGES = frozenset({"Go", "Rust"})


class ContractError(ValueError):
    """The frozen paired-evaluation contract was violated."""


class TerminalState(StrEnum):
    CONFIRMED = "confirmed"
    KILLED = "killed"
    UNRESOLVED = "unresolved"
    ABSTAINED = "abstained"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    BUDGET_EXHAUSTED = "budget_exhausted"
    PARSER_FAILED = "parser_failed"
    VERIFIER_FAILED = "verifier_failed"
    VERIFIER_UNSUPPORTED = "verifier_unsupported"
    NOT_APPLICABLE = "not_applicable"


class SyntheticOutcome(StrEnum):
    ACTIONABLE = "actionable"
    NON_ACTIONABLE = "non_actionable"


@dataclass(frozen=True)
class PairedObservation:
    identity: str
    arm: str
    terminal_state: TerminalState
    source_family: str
    language: str
    mechanism: str | None
    detector: str
    outcome: SyntheticOutcome | None = None
    usage_available: bool = True
    provider_tokens: int | None = 0
    provider_latency_ms: int | None = 0
    known_cost_usd: float | None = 0.0


@dataclass(frozen=True)
class ArmMetrics:
    identities: int
    unique_validated_issues: int
    precision: float | None
    recall: float | None
    abstention_coverage: float
    provider_tokens: int | None
    provider_latency_ms: int | None
    known_cost_usd: float | None
    cost_per_unique_validated_issue: float | None


def eval_tool_config() -> AgentReadOnlyToolsConfig:
    """Return the exact eval-only facade bounds without touching global config."""
    return AgentReadOnlyToolsConfig(
        enabled=True,
        allowlist=[
            "indexed_source_excerpt",
            "structural_slice",
            "callers",
            "references",
            "architecture_evidence",
        ],
        maximum_calls=12,
        maximum_results_per_call=5,
        maximum_context_lines=12,
        maximum_query_characters=256,
        maximum_response_bytes=32768,
    )


def build_eval_tool_session(
    *,
    index: RetrievalIndex,
    finding: Finding,
    architecture: ArchitectureMap,
    snapshot_commit: str,
    expected_index_digest: str,
) -> AgentReadOnlyTools:
    """Construct only the existing bounded facade from in-memory trusted inputs."""
    return AgentReadOnlyTools(
        index=index,
        finding=finding,
        architecture=architecture,
        snapshot_commit=snapshot_commit,
        expected_index_digest=expected_index_digest,
        config=eval_tool_config(),
    )


def _group_pairs(
    observations: Iterable[PairedObservation],
) -> dict[str, dict[str, PairedObservation]]:
    grouped: dict[str, dict[str, PairedObservation]] = defaultdict(dict)
    for item in observations:
        if not item.identity or not item.source_family or not item.detector:
            raise ContractError("identity, family, and detector bindings are required")
        if item.arm not in ARMS:
            raise ContractError("arm is outside the frozen pair")
        if item.arm in grouped[item.identity]:
            raise ContractError("duplicate arm observation")
        grouped[item.identity][item.arm] = item
    if not grouped:
        raise ContractError("paired observation set is empty")
    for identity, pair in grouped.items():
        if set(pair) != set(ARMS):
            raise ContractError(f"missing arm observation for {identity}")
        baseline, agent = pair["baseline"], pair["agent"]
        bindings = ("source_family", "language", "mechanism", "detector", "outcome")
        if any(getattr(baseline, field) != getattr(agent, field) for field in bindings):
            raise ContractError("paired metadata or blinded outcome drift")
        if baseline.language in UNSUPPORTED_LANGUAGES:
            if baseline.mechanism is not None or any(
                item.terminal_state is not TerminalState.VERIFIER_UNSUPPORTED
                for item in pair.values()
            ):
                raise ContractError("unsupported language must retain paired verifier_unsupported states")
        elif (
            baseline.language not in SUPPORTED_CELLS
            or baseline.mechanism not in SUPPORTED_CELLS[baseline.language]
        ):
            raise ContractError("identity is outside the frozen supported envelope")
    return dict(grouped)


def validate_complete_pairs(observations: Iterable[PairedObservation]) -> int:
    """Validate pairing/envelope invariants and return the outer denominator."""
    return len(_group_pairs(observations))


def _metrics(items: list[PairedObservation]) -> ArmMetrics:
    decided = [item for item in items if item.language not in UNSUPPORTED_LANGUAGES]
    positives = sum(item.outcome is SyntheticOutcome.ACTIONABLE for item in decided)
    confirmed = [item for item in decided if item.terminal_state is TerminalState.CONFIRMED]
    true_positives = sum(item.outcome is SyntheticOutcome.ACTIONABLE for item in confirmed)
    abstentions = sum(
        item.terminal_state not in {TerminalState.CONFIRMED, TerminalState.KILLED}
        for item in decided
    )
    usage_complete = all(
        item.usage_available
        and item.provider_tokens is not None
        and item.provider_latency_ms is not None
        and item.known_cost_usd is not None
        for item in decided
    )
    tokens = sum(item.provider_tokens or 0 for item in decided) if usage_complete else None
    latency = sum(item.provider_latency_ms or 0 for item in decided) if usage_complete else None
    cost = sum(item.known_cost_usd or 0.0 for item in decided) if usage_complete else None
    return ArmMetrics(
        identities=len(decided),
        unique_validated_issues=true_positives,
        precision=(true_positives / len(confirmed)) if confirmed else None,
        recall=(true_positives / positives) if positives else None,
        abstention_coverage=(abstentions / len(decided)) if decided else 0.0,
        provider_tokens=tokens,
        provider_latency_ms=latency,
        known_cost_usd=cost,
        cost_per_unique_validated_issue=(cost / true_positives)
        if cost is not None and true_positives
        else None,
    )


def _both_classes(items: list[PairedObservation]) -> bool:
    outcomes = {item.outcome for item in items if item.language not in UNSUPPORTED_LANGUAGES}
    return outcomes == {SyntheticOutcome.ACTIONABLE, SyntheticOutcome.NON_ACTIONABLE}


def _subgroup_availability(
    pairs: dict[str, dict[str, PairedObservation]],
) -> dict[str, list[str]]:
    unavailable: dict[str, list[str]] = {}
    baseline = [pair["baseline"] for pair in pairs.values()]
    for field in ("source_family", "mechanism", "language", "detector"):
        values = sorted({str(getattr(item, field)) for item in baseline if item.language not in UNSUPPORTED_LANGUAGES})
        missing = [
            value
            for value in values
            if not _both_classes([
                item for item in baseline if str(getattr(item, field)) == value
            ])
        ]
        if missing:
            unavailable[field] = missing
    return unavailable


def evaluate_paired(
    observations: Iterable[PairedObservation],
) -> dict[str, object]:
    """Evaluate synthetic blinded outcomes under the frozen G03b/G04 rules."""
    pairs = _group_pairs(observations)
    if any(item.outcome is None for pair in pairs.values() for item in pair.values()):
        raise ContractError("outcomes remain unavailable")
    baseline_items = [pair["baseline"] for pair in pairs.values()]
    agent_items = [pair["agent"] for pair in pairs.values()]
    baseline = _metrics(baseline_items)
    agent = _metrics(agent_items)
    monotonic_failures = sorted(
        identity
        for identity, pair in pairs.items()
        if pair["baseline"].language not in UNSUPPORTED_LANGUAGES
        and pair["baseline"].outcome is SyntheticOutcome.ACTIONABLE
        and pair["baseline"].terminal_state is TerminalState.CONFIRMED
        and pair["agent"].terminal_state is not TerminalState.CONFIRMED
    )
    unavailable_subgroups = _subgroup_availability(pairs)
    g04 = (
        baseline.recall is not None
        and agent.recall is not None
        and agent.recall >= baseline.recall
        and not monotonic_failures
    )
    comparable = all(
        value is not None
        for value in (
            baseline.precision,
            baseline.recall,
            baseline.cost_per_unique_validated_issue,
            agent.precision,
            agent.recall,
            agent.cost_per_unique_validated_issue,
        )
    )
    no_worse = comparable and (
        agent.unique_validated_issues >= baseline.unique_validated_issues
        and agent.precision >= baseline.precision  # type: ignore[operator]
        and agent.recall >= baseline.recall  # type: ignore[operator]
        and agent.abstention_coverage <= baseline.abstention_coverage
        and agent.cost_per_unique_validated_issue
        <= baseline.cost_per_unique_validated_issue  # type: ignore[operator]
    )
    strict = comparable and any((
        agent.unique_validated_issues > baseline.unique_validated_issues,
        agent.precision > baseline.precision,  # type: ignore[operator]
        agent.recall > baseline.recall,  # type: ignore[operator]
        agent.abstention_coverage < baseline.abstention_coverage,
        agent.cost_per_unique_validated_issue
        < baseline.cost_per_unique_validated_issue,  # type: ignore[operator]
    ))
    usage_complete = all(
        item.usage_available for pair in pairs.values() for item in pair.values()
        if item.language not in UNSUPPORTED_LANGUAGES
    )
    g03b = bool(
        g04
        and no_worse
        and strict
        and usage_complete
        and not unavailable_subgroups
        and _both_classes(baseline_items)
    )
    return {
        "outer_denominator": len(pairs),
        "supported_denominator": baseline.identities,
        "unsupported_outer_denominator": sum(
            pair["baseline"].language in UNSUPPORTED_LANGUAGES
            for pair in pairs.values()
        ),
        "baseline": baseline,
        "agent": agent,
        "monotonic_recall_failures": monotonic_failures,
        "unavailable_subgroups": unavailable_subgroups,
        "G04_pass": g04,
        "G03b_pass": g03b,
    }
