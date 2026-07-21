"""Map stage — architecture/trust-boundary recovery, run before detection."""

from .domain_map import load_architecture, recover_architecture
from .schema import (
    ArchitectureExtraction,
    ArchitectureMap,
    DataStore,
    EntryPoint,
    Integration,
    TrustBoundary,
)

__all__ = [
    "recover_architecture",
    "load_architecture",
    "ArchitectureExtraction",
    "ArchitectureMap",
    "TrustBoundary",
    "EntryPoint",
    "DataStore",
    "Integration",
]
