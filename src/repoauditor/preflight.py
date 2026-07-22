"""Operational preflight checks for CLI workflows.

This module checks runtime availability only; it does not install software or alter
pipeline behavior. SQLite initialization remains delegated to `store.db`.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel, ConfigDict

from .config import Config
from .llm.client import LLMClient, get_llm_client
from .store import db


_PYTHON_MODULES = {
    "anthropic": "anthropic",
    "GitPython": "git",
    "httpx": "httpx",
    "matplotlib": "matplotlib",
    "NumPy": "numpy",
    "Pydantic": "pydantic",
    "PyYAML": "yaml",
    "scikit-learn": "sklearn",
    "SciPy": "scipy",
    "SHAP": "shap",
    "tree-sitter": "tree_sitter",
    "tree-sitter-language-pack": "tree_sitter_language_pack",
    "Typer": "typer",
    "XGBoost": "xgboost",
}
_SCANNERS = ("semgrep", "gitleaks", "pip-audit", "osv-scanner")


@dataclass
class PreflightResult:
    migrations: list[str] = field(default_factory=list)
    missing_packages: list[str] = field(default_factory=list)
    missing_scanners: list[str] = field(default_factory=list)
    credential_error: str | None = None
    git_available: bool = True
    scanners_checked: bool = True

    @property
    def ready(self) -> bool:
        return not self.missing_packages and self.credential_error is None


class _ModelProbe(BaseModel):
    """Small strict response used to exercise the production reliability path."""

    model_config = ConfigDict(extra="forbid")
    status: Literal["ready"]


@dataclass(frozen=True)
class ModelCheckResult:
    provider: str
    model: str
    response_format: str
    error: str | None = None

    @property
    def ready(self) -> bool:
        return self.error is None


def check_runtime(config: Config) -> PreflightResult:
    """Initialize the store and inspect required packages, credentials, and tools."""
    result = PreflightResult(migrations=db.init_db(config))
    required_modules = dict(_PYTHON_MODULES)
    if config.llm.provider != "anthropic":
        required_modules.pop("anthropic")
    result.missing_packages = [
        name for name, module in required_modules.items()
        if importlib.util.find_spec(module) is None
    ]

    if config.llm.provider == "anthropic":
        if not os.environ.get("ANTHROPIC_API_KEY"):
            result.credential_error = "ANTHROPIC_API_KEY is not set"
    elif config.llm.api_key_env and not os.environ.get(config.llm.api_key_env):
        result.credential_error = f"{config.llm.api_key_env} is not set"

    result.git_available = shutil.which("git") is not None
    result.scanners_checked = config.detect.run_deterministic_tools
    if config.detect.run_deterministic_tools:
        result.missing_scanners = [tool for tool in _SCANNERS if shutil.which(tool) is None]
    return result


def check_model(config: Config, client: LLMClient | None = None) -> ModelCheckResult:
    """Make one minimal validated model call.

    This is intentionally separate from :func:`check_runtime`: callers must opt in
    because it reaches the configured endpoint and may incur provider charges.  The
    shared client exercises backend connectivity/auth/model selection, the configured
    response-format mode, bounded retries, and authoritative Pydantic validation.
    """
    try:
        (client or get_llm_client(config)).call(
            module="doctor",
            prompt_version="model_probe_v1",
            system="You are a connectivity diagnostic. Return only the requested schema.",
            user='Return the JSON object {"status":"ready"}.',
            schema=_ModelProbe,
            context={"stage": "doctor", "check": "model"},
        )
    except Exception as exc:
        return ModelCheckResult(
            provider=config.llm.provider,
            model=config.model.name,
            response_format=config.llm.response_format,
            error=f"{type(exc).__name__}: {exc}",
        )
    return ModelCheckResult(
        provider=config.llm.provider,
        model=config.model.name,
        response_format=config.llm.response_format,
    )
