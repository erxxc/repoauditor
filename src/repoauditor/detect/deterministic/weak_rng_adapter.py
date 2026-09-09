"""Weak-RNG adapter — repoauditor's own source detector for predictable generators.

Unlike the tool-wrapping adapters (SAST/SCA/secrets), there is no external scanner for
the taxonomy's middle branch: a *shared/predictable generator crossing a trust
boundary* (session tokens, reset codes, CSRF/nonces seeded from `java.util.Random`,
unseeded `new Random()`, Apache Commons `RandomStringUtils`). SAST rule packs, SCA, and
CVE feeds do not flag it — it is a correct-looking use of a standard-library API. Yet
`java.util.Random` is a 48-bit truncated LCG whose full internal state is recoverable
from a handful of outputs (the Randar attack; see the `prng-lattice-lab` harness), so
anything it seeds is predictable.

This adapter locates those idioms syntactically over the retrieval index (tree-sitter /
lexical), emitting canonical `CandidateFinding`s. It proposes a conservative INITIAL
severity only; `normalize/adjudicate` owns upgrades, and the corroborating source that
licenses one is a reproducible state-recovery demonstration (built in the harness), not
a prior. Matching is syntactic, so findings are review candidates, never automatic
actionable findings.

Scope (OPT-036): Java idioms. The adapter is registered as a first-class deterministic
scanner with explicit execution evidence and deployment canaries. The
`nextint_odd`/`bit_length` leak-model breadth and other languages remain follow-ups.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from ..ensemble import CandidateFinding
from ..retrieval.index import RetrievalIndex
from ...sourcefiles import is_test_source, iter_source_files
from ...store.models import Severity
from .execution import ScannerExecution

logger = logging.getLogger(__name__)

TOOL_NAME = "weak_rng"
_VERSION = "weak_rng@v1"
_CONFIGURATION = "weak_rng builtin idioms"       # embedded rules; digested identity below
_INVOCATION = ("weak_rng", "scan", "$SNAPSHOT")  # index-driven, no external process

_TEST_DIRS = {"test", "tests", "spec", "specs", "__tests__"}  # mirrors sourcefiles
_COMMENT_PREFIXES = ("//", "*", "/*", "#")


@dataclass(frozen=True)
class _Idiom:
    """One predictable-RNG idiom: which literal tokens signal it, where it applies,
    and how it is described. `exclude` tokens veto a line (e.g. SecureRandom)."""

    idiom_id: str
    tokens: tuple[str, ...]
    suffixes: tuple[str, ...]
    title: str
    confidence: float
    rationale: str
    exclude: tuple[str, ...] = field(default_factory=tuple)

    def matches(self, line: str) -> bool:
        return any(t in line for t in self.tokens) and not any(x in line for x in self.exclude)


# Ordered by specificity; the first idiom that matches a line owns it.
_IDIOMS: tuple[_Idiom, ...] = (
    _Idiom(
        idiom_id="java-util-random-ctor",
        tokens=("new Random(", "new java.util.Random("),
        suffixes=(".java",),
        title="Predictable RNG: java.util.Random in a security context",
        confidence=0.75,
        rationale=("java.util.Random is a 48-bit truncated LCG; its full internal state is "
                   "recoverable from a few outputs (Randar), so any token/id/nonce seeded from "
                   "it is predictable once it crosses a trust boundary. Use SecureRandom."),
    ),
    _Idiom(
        idiom_id="math-random",
        tokens=("Math.random(",),
        suffixes=(".java",),
        title="Predictable RNG: Math.random()",
        confidence=0.65,
        rationale=("Math.random() is backed by a shared java.util.Random (the same recoverable "
                   "LCG); values derived from it are predictable across a trust boundary."),
    ),
    _Idiom(
        idiom_id="apache-randomstringutils",
        tokens=("RandomStringUtils.random",),
        suffixes=(".java",),
        title="Predictable RNG: Apache Commons RandomStringUtils",
        confidence=0.7,
        rationale=("Apache Commons RandomStringUtils draws from java.util.Random by default "
                   "(the elttam case); generated identifiers/tokens are predictable. Prefer the "
                   "secure() variants or a CSPRNG."),
        exclude=("RandomStringUtils.secure",),
    ),
)


def _is_test_path(index: RetrievalIndex, file: str) -> bool:
    """Use repoauditor's canonical test-source classifier when the snapshot root is
    known; fall back to a path-parts check on the same test-dir set otherwise."""
    root = index.snapshot_path
    if root is not None:
        return is_test_source(root / file, root)
    return bool({part.lower() for part in file.split("/")[:-1]} & _TEST_DIRS)


def _is_comment(stripped: str) -> bool:
    return stripped.startswith(_COMMENT_PREFIXES)


def _identity(index: RetrievalIndex, file: str, line: int, idiom_id: str) -> str:
    """Stable natural identity for matching.py: the enclosing symbol (falls back to the
    line) plus the idiom, so re-runs collapse the same issue and distinct issues stay
    distinct."""
    enclosing = index.find_enclosing(file, line)
    symbol = enclosing[0].symbol if enclosing else f"line{line}"
    return f"weak-rng:{file}:{symbol}:{idiom_id}"


def detect_in_source(index: RetrievalIndex) -> list[CandidateFinding]:
    """Locate predictable-RNG idioms in an indexed snapshot.

    Pure over the retrieval index (no snapshot I/O of its own, no external tool), so it
    reuses the index run_ensemble already builds. Returns canonical candidates with a
    conservative initial severity; comments and test sources are skipped and each
    (file, line) is reported once.
    """
    candidates: list[CandidateFinding] = []
    seen: set[tuple[str, int]] = set()
    for idiom in _IDIOMS:
        hits: dict[tuple[str, int], str] = {}
        for token in idiom.tokens:
            # context_lines=0 -> one hit per matching line, line_start is the exact line,
            # source is that line. A high limit collects every occurrence.
            for hit in index.find_text_references(token, limit=100_000, context_lines=0):
                hits[(hit.file, hit.line_start)] = hit.source
        for (file, line), source in sorted(hits.items()):
            if (file, line) in seen:
                continue
            if not any(file.endswith(suffix) for suffix in idiom.suffixes):
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
                trust_boundary_ref=None,    # persistence falls back to the primary boundary
                rationale=idiom.rationale,
            ))
    logger.info("weak_rng: %d candidate(s) across the snapshot", len(candidates))
    return candidates


class WeakRngAdapter:
    """First-class deterministic scanner adapter for the weak-RNG detector.

    Mirrors the tool adapters' surface (`run` + `execution` + `run_status`/`failure_detail`)
    but shells out to nothing — detection is index-driven. Applicability is the presence of
    Java source; `target_count` is the number of `.java` files considered
    (basis `scanner-reported-files`), so a clean zero (empty) is distinguishable from
    not-applicable (no Java) and from a failure, per the OPT-022 execution contract.
    """

    tool_name = TOOL_NAME

    def __init__(self, timeout_seconds: int = 0) -> None:
        # timeout accepted for a uniform adapter signature; there is no subprocess.
        self.run_status: str | None = None
        self.failure_detail: str | None = None
        self._target_count = 0
        self._finding_count = 0
        self._applicable: bool | None = None
        self._applicability_detail: str | None = None

    def run(self, snapshot_path, index: RetrievalIndex | None = None) -> list[CandidateFinding]:
        snapshot_path = Path(snapshot_path)
        java_files = [p for p in iter_source_files(snapshot_path) if p.suffix.lower() == ".java"]
        self._target_count = len(java_files)
        if not java_files:
            self._applicable = False
            self._applicability_detail = "snapshot contains no .java source"
            self.run_status = "not-applicable"
            return []
        self._applicable = True
        if index is not None:
            if (
                index.snapshot_path is None
                or index.snapshot_path.resolve() != snapshot_path.resolve()
            ):
                raise ValueError("retrieval index is not bound to the submitted snapshot")
        index = index or RetrievalIndex().build(snapshot_path)
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
                applicability_detail=self._applicability_detail or "no .java source",
                **common,
            )
        if status == "failed":
            return ScannerExecution(
                status="failed", applicable=self._applicable, output_valid=False,
                finding_count=0, target_count=self._target_count,
                target_count_basis="scanner-reported-files",
                failure_detail=self.failure_detail or "weak_rng adapter failed",
                **common,
            )
        return ScannerExecution(   # complete | empty
            status=status, applicable=True, output_valid=True,
            finding_count=self._finding_count, target_count=self._target_count,
            target_count_basis="scanner-reported-files", **common,
        )
