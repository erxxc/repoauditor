"""Package-local registration for the Java weak-RNG detector."""

from __future__ import annotations

from pathlib import Path

from ..weak_rng_adapter import WeakRngAdapter


def create_adapter(timeout_seconds: int) -> WeakRngAdapter:
    return WeakRngAdapter(timeout_seconds)


def run_canary(root: Path, timeout_seconds: int):
    # Imported lazily so canary model construction does not participate in package import
    # order and the plugin seam stays independent of the orchestration module.
    from ..canaries import (
        ScannerCanaryResult,
        _clean_probe,
        _positive_probe,
        _provenance_passed,
        _write,
    )

    positive_root = root / "weak-rng-positive"
    clean_root = root / "weak-rng-clean"
    _write(
        positive_root,
        "TokenService.java",
        "import java.util.Random;\nclass TokenService { String token() { "
        "return String.valueOf(new Random().nextLong()); } }\n",
    )
    _write(
        clean_root,
        "TokenService.java",
        "import java.security.SecureRandom;\nclass TokenService { "
        "SecureRandom rng = new SecureRandom(); }\n",
    )
    positive_adapter = create_adapter(timeout_seconds)
    positive_adapter.run(positive_root)
    clean_adapter = create_adapter(timeout_seconds)
    clean_adapter.run(clean_root)
    positive = _positive_probe(positive_adapter.execution())
    clean = _clean_probe(clean_adapter.execution())
    provenance_passed = _provenance_passed("weak_rng", positive, clean)
    return ScannerCanaryResult(
        scanner="weak_rng",
        passed=positive.passed and clean.passed and provenance_passed,
        provenance_passed=provenance_passed,
        positive=positive,
        clean=clean,
    )
