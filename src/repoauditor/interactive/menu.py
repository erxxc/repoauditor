"""Read-only state and rendering for the numbered interactive menu.

The menu does not run pipeline stages. It reads state through store/review APIs and returns
plain text; the thin CLI remains responsible for prompts and command dispatch.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..config import Config
from ..review import open_review_requests
from ..store import db


@dataclass(frozen=True)
class RepositoryState:
    repo_id: str
    source: str
    open_reviews: int


@dataclass(frozen=True)
class MenuState:
    repositories: tuple[RepositoryState, ...]

    @property
    def open_reviews(self) -> int:
        return sum(repo.open_reviews for repo in self.repositories)


def load_menu_state(config: Config) -> MenuState:
    """Load latest repositories and review counts through public store APIs."""
    db.init_db(config)
    repositories = db.list_ingested_repos(config, all_snapshots=False)
    return MenuState(tuple(
        RepositoryState(
            repo_id=repo.repo_id,
            source=repo.source,
            open_reviews=len(open_review_requests(repo.repo_id, config)),
        )
        for repo in repositories
    ))


def render_main_menu(state: MenuState) -> str:
    """Render a compact menu that remains readable over SSH and screen sharing."""
    repo_count = len(state.repositories)
    review_note = (
        f" ({state.open_reviews} pending)" if state.open_reviews else " (none pending)"
    )
    width = 47

    def row(label: str) -> str:
        return f"│ {label:<{width - 2}} │"

    return "\n".join([
        "┌" + "─" * width + "┐",
        row("RepoAuditor"),
        "├" + "─" * width + "┤",
        row("1. Run guided demo"),
        row("2. Scan a repository"),
        row(f"3. Review pending findings{review_note}"),
        row("4. Finalize reports"),
        row(f"5. View repositories and run history ({repo_count})"),
        row("6. Check installation"),
        row("7. Exit"),
        "└" + "─" * width + "┘",
    ])
