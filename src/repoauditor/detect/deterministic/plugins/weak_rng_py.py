"""Package-local weak-RNG detector for Python's `random` module (`weak_rng_py`).

The second plugin behind the bounded scanner extension seam, and deliberately a
SEPARATE plugin from the Java `weak_rng` detector: that adapter's files are digest-bound
by the OPT-036 requalification result, so new coverage is added beside it, never by
editing it. Everything this plugin needs lives in this module (adapter, idioms, canary
with its own provenance check); it imports the Java module's two small path/comment
helpers read-only.

Mechanism: Python's `random` is MT19937. Its full 32-bit outputs untemper exactly, so
624 consecutive `getrandbits(32)`-class outputs reconstruct the whole state and every
past/future output (demonstrated, verified, in the standalone `prng-lattice-lab`:
`demonstrate mt19937`). Derived outputs (`random()`, `randint`, `choice`, ...) come from
the same generator and are predictable to the same attacker; the exact-clone
demonstration covers the full-word case, so those idioms carry a lower confidence.
`secrets` and `random.SystemRandom` are never matched.

This is deliberately substring-only coverage. Aliased imports are missed, while shadowed
``random`` identifiers and string literals can match. Claim boundary is the Java detector's:
syntactic candidates with a conservative
initial MEDIUM severity; `normalize/adjudicate` owns any upgrade, licensed only by an
independent corroborating source (a reproducible recovery demonstration), never by
this detector's say-so.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from ...ensemble import CandidateFinding
from ...retrieval.index import RetrievalIndex
from ....sourcefiles import iter_source_files
from ....store.models import Severity
from ..execution import ScannerExecution
from ..weak_rng_adapter import _is_comment, _is_test_path  # read-only helpers

logger = logging.getLogger(__name__)

TOOL_NAME = "weak_rng_py"
_VERSION = "weak_rng_py@v1"
_CONFIGURATION = "weak_rng_py builtin idioms"
_INVOCATION = (TOOL_NAME, "scan", "$SNAPSHOT")
_EXCLUDE = ("SystemRandom", "secrets.")


@dataclass(frozen=True)
class _Idiom:
    idiom_id: str
    tokens: tuple[str, ...]
    title: str
    confidence: float
    rationale: str
    exclude: tuple[str, ...] = field(default_factory=lambda: _EXCLUDE)

    def matches(self, line: str) -> bool:
        return any(t in line for t in self.tokens) and not any(x in line for x in self.exclude)


# Ordered by specificity; the first idiom that matches a line owns it.
_IDIOMS: tuple[_Idiom, ...] = (
    _Idiom(
        idiom_id="py-random-getrandbits",
        tokens=("random.getrandbits(",),
        title="Predictable RNG: random.getrandbits() in a security context",
        confidence=0.75,
        rationale=("Python's random module is MT19937; full-word outputs untemper exactly, so "
                   "624 consecutive outputs reconstruct the state and every past/future value "
                   "(verified: prng-lattice-lab `demonstrate mt19937`). A token built from "
                   "getrandbits is predictable once it crosses a trust boundary. Use secrets."),
    ),
    _Idiom(
        idiom_id="py-random-ctor",
        tokens=("random.Random(",),
        title="Predictable RNG: random.Random() instance in a security context",
        confidence=0.6,
        rationale=("A random.Random instance is MT19937 (often seeded from time or a small "
                   "value); its outputs are predictable from observed outputs or a guessable "
                   "seed. Use secrets / random.SystemRandom."),
    ),
    _Idiom(
        idiom_id="py-random-module",
        tokens=("random.random(", "random.randint(", "random.randrange(", "random.choice(",
                "random.choices(", "random.sample(", "random.uniform(", "random.shuffle("),
        title="Predictable RNG: random module output in a security context",
        confidence=0.6,
        rationale=("random.random()/randint/choice/... draw from the module-global MT19937. "
                   "Derived outputs expose truncated words, so the exact-clone demonstration "
                   "covers full-word outputs; the generator class is the same and predictable "
                   "across a trust boundary. Use secrets."),
    ),
)


def _identity(index: RetrievalIndex, file: str, line: int, idiom_id: str) -> str:
    enclosing = index.find_enclosing(file, line)
    symbol = enclosing[0].symbol if enclosing else f"line{line}"
    return f"weak-rng-py:{file}:{symbol}:{idiom_id}"


def detect_in_source(index: RetrievalIndex) -> list[CandidateFinding]:
    """Locate predictable-RNG idioms in Python source over the retrieval index."""
    candidates: list[CandidateFinding] = []
    seen: set[tuple[str, int]] = set()
    for idiom in _IDIOMS:
        hits: dict[tuple[str, int], str] = {}
        for token in idiom.tokens:
            for hit in index.find_text_references(token, limit=100_000, context_lines=0):
                hits[(hit.file, hit.line_start)] = hit.source
        for (file, line), source in sorted(hits.items()):
            if (file, line) in seen or not file.endswith(".py"):
                continue
            if _is_test_path(index, file):
                continue
            stripped = source.strip()
            if _is_comment(stripped) or not idiom.matches(source):
                continue
            seen.add((file, line))
            candidates.append(CandidateFinding(
                title=idiom.title,
                file=file,
                line_start=line,
                line_end=line,
                citation_snippet=stripped[:200],
                identity_key=_identity(index, file, line, idiom.idiom_id),
                source_tool=TOOL_NAME,
                producer=idiom.idiom_id,
                confidence=idiom.confidence,
                severity=Severity.MEDIUM,   # conservative initial; normalize owns upgrades
                trust_boundary_ref=None,
                rationale=idiom.rationale,
            ))
    logger.info("weak_rng_py: %d candidate(s) across the snapshot", len(candidates))
    return candidates


class WeakRngPyAdapter:
    """Deterministic scanner adapter for the Python weak-RNG detector (OPT-022
    execution contract; applicability = presence of non-test `.py` source)."""

    tool_name = TOOL_NAME

    def __init__(self, timeout_seconds: int = 0) -> None:
        self.run_status: str | None = None
        self.failure_detail: str | None = None
        self._target_count = 0
        self._finding_count = 0
        self._applicable: bool | None = None
        self._applicability_detail: str | None = None

    def run(self, snapshot_path, index: RetrievalIndex | None = None) -> list[CandidateFinding]:
        snapshot_path = Path(snapshot_path)
        if index is not None and (
            index.snapshot_path is None
            or index.snapshot_path.resolve() != snapshot_path.resolve()
        ):
            raise ValueError("retrieval index is not bound to the submitted snapshot")
        index = index or RetrievalIndex().build(snapshot_path)
        py_files = [
            path
            for path in iter_source_files(snapshot_path)
            if path.suffix.lower() == ".py"
            and not _is_test_path(index, path.relative_to(snapshot_path).as_posix())
        ]
        self._target_count = len(py_files)
        if not py_files:
            self._applicable = False
            self._applicability_detail = "snapshot contains no .py source"
            self.run_status = "not-applicable"
            return []
        self._applicable = True
        candidates = detect_in_source(index)
        self._finding_count = len(candidates)
        self.run_status = "complete" if candidates else "empty"
        return candidates

    def execution(self) -> ScannerExecution:
        status = self.run_status or "failed"
        common = dict(
            scanner=TOOL_NAME, version=_VERSION, invocation=_INVOCATION,
            configuration=_CONFIGURATION, configuration_resolution="embedded-default",
        )
        if status == "not-applicable":
            return ScannerExecution(
                status="not-applicable", applicable=False, output_valid=False,
                finding_count=0, target_count=0, target_count_basis="not-applicable",
                applicability_detail=self._applicability_detail or "no .py source", **common,
            )
        if status == "failed":
            return ScannerExecution(
                status="failed", applicable=self._applicable, output_valid=False,
                finding_count=0, target_count=self._target_count,
                target_count_basis="scanner-reported-files",
                failure_detail=self.failure_detail or "weak_rng_py adapter failed", **common,
            )
        return ScannerExecution(
            status=status, applicable=True, output_valid=True,
            finding_count=self._finding_count, target_count=self._target_count,
            target_count_basis="scanner-reported-files", **common,
        )


def create_adapter(timeout_seconds: int) -> WeakRngPyAdapter:
    return WeakRngPyAdapter(timeout_seconds)


def _provenance_passed(positive, clean) -> bool:
    """This plugin's own provenance rule (the orchestration module's table is digest-
    bound, so a plugin must certify its embedded identity itself): both probes ran the
    embedded weak_rng_py@v1 idiom set."""
    return all(
        item.version == _VERSION
        and tuple(item.invocation) == _INVOCATION
        and item.configuration == _CONFIGURATION
        and item.configuration_resolution == "embedded-default"
        for item in (positive.execution, clean.execution)
    )


def run_canary(root: Path, timeout_seconds: int):
    from ..canaries import ScannerCanaryResult, _clean_probe, _positive_probe, _write

    positive_root = root / "weak-rng-py-positive"
    clean_root = root / "weak-rng-py-clean"
    _write(positive_root, "token_service.py",
           "import random\n\n\ndef token():\n    return hex(random.getrandbits(128))\n")
    _write(clean_root, "token_service.py",
           "import secrets\n\n\ndef token():\n    return secrets.token_hex(16)\n")
    positive_adapter = create_adapter(timeout_seconds)
    positive_adapter.run(positive_root)
    clean_adapter = create_adapter(timeout_seconds)
    clean_adapter.run(clean_root)
    positive = _positive_probe(positive_adapter.execution())
    clean = _clean_probe(clean_adapter.execution())
    provenance_passed = _provenance_passed(positive, clean)
    return ScannerCanaryResult(
        scanner=TOOL_NAME,
        passed=positive.passed and clean.passed and provenance_passed,
        provenance_passed=provenance_passed,
        positive=positive,
        clean=clean,
    )
