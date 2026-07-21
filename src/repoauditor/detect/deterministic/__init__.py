"""Deterministic tool adapters.

Each adapter wraps an external tool's output (SAST / SCA / secret scanner) into the
canonical candidate-finding shape so deterministic results sit alongside the AI
lenses in one normalization step. Interface stubs only: no real tool integration yet.
"""

from .sast_adapter import SastAdapter
from .sca_adapter import ScaAdapter
from .secrets_adapter import SecretsAdapter

__all__ = ["SastAdapter", "ScaAdapter", "SecretsAdapter"]
