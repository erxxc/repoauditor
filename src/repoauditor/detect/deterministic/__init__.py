"""Deterministic tool adapters.

Each adapter wraps an external tool's output (SAST=Semgrep, SCA=pip-audit+OSV-Scanner,
secrets=gitleaks) into the canonical candidate-finding shape so deterministic results
sit alongside the AI lenses in one normalization step. Every adapter degrades to no
findings when its binary is absent, so a partial toolchain never breaks a run.
"""

from .sast_adapter import SastAdapter
from .sca_adapter import ScaAdapter
from .secrets_adapter import SecretsAdapter

__all__ = ["SastAdapter", "ScaAdapter", "SecretsAdapter"]
