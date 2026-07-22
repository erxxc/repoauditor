"""Normalize stage — adjudicate conflicting severity across tools/lenses into schema.

Writes everything into the canonical `store.models.Finding` shape. Interface stub.
"""

from .adjudicate import Adjudication, adjudicate, adjudicate_repo

__all__ = ["adjudicate", "adjudicate_repo", "Adjudication"]
