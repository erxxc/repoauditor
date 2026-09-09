"""Deterministic tool adapters.

Each adapter wraps an external tool's output (SAST=Semgrep, SCA=pip-audit+OSV-Scanner,
secrets=gitleaks) into the canonical candidate-finding shape so deterministic results
sit alongside the AI lenses in one normalization step. Every adapter degrades to no
findings when its binary is absent, so a partial toolchain never breaks a run.
"""

from .sast_adapter import SastAdapter
from .sca_adapter import ScaAdapter
from .secrets_adapter import SecretsAdapter
from .weak_rng_adapter import WeakRngAdapter
from .execution import DETERMINISTIC_SCANNERS, ScannerExecution
from .canaries import (
    ScannerCanaryReport,
    render_scanner_canaries,
    run_scanner_canaries,
)

__all__ = [
    "SastAdapter",
    "ScaAdapter",
    "SecretsAdapter",
    "WeakRngAdapter",
    "ScannerExecution",
    "DETERMINISTIC_SCANNERS",
    "ScannerCanaryReport",
    "run_scanner_canaries",
    "render_scanner_canaries",
]
