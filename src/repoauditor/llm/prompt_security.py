"""Shared prompt boundary for treating repository-controlled text as untrusted data."""

from __future__ import annotations

from pathlib import Path

PROMPT_SECURITY_VERSION = "untrusted_repository_content_v1"
PROMPT_SECURITY = (
    Path(__file__).parent / "prompts" / f"{PROMPT_SECURITY_VERSION}.md"
).read_text()

_BEGIN = "<<<BEGIN UNTRUSTED REPOSITORY EVIDENCE>>>"
_END = "<<<END UNTRUSTED REPOSITORY EVIDENCE>>>"


def secure_system_prompt(stage_prompt: str) -> str:
    """Compose a stage prompt with the shared untrusted-content policy."""
    return f"{stage_prompt.rstrip()}\n\n{PROMPT_SECURITY}"


def delimit_repository_evidence(content: str) -> str:
    """Make the trust boundary explicit in the user message."""
    return f"{_BEGIN}\n{content}\n{_END}"
