"""Numbered ASCII menu behavior without changing the command-oriented CLI surface."""

from __future__ import annotations

from typer.testing import CliRunner

from repoauditor import cli
from repoauditor.interactive import MenuState, RepositoryState, render_main_menu


runner = CliRunner()


def test_menu_renders_state_counts_and_aligned_box():
    text = render_main_menu(MenuState((
        RepositoryState("a", "/a", 2), RepositoryState("b", "/b", 0),
    )))
    assert "2 pending" in text
    assert "run history (2)" in text
    widths = {len(line) for line in text.splitlines()}
    assert len(widths) == 1


def test_explicit_menu_can_exit_without_side_effects(tmp_config, monkeypatch):
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    result = runner.invoke(cli.app, ["menu"], input="7\n")
    assert result.exit_code == 0
    assert "RepoAuditor" in result.output and "Goodbye" in result.output


def test_no_args_non_tty_prints_help_instead_of_prompting():
    result = runner.invoke(cli.app, [])
    assert result.exit_code == 0
    assert "Usage:" in result.output
    assert "Select an option" not in result.output


def test_scan_menu_dispatches_existing_run_command(tmp_config, monkeypatch):
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    calls = []
    monkeypatch.setattr(
        cli, "run", lambda source, output_format, fresh: calls.append(
            (source, output_format, fresh)
        ),
    )
    result = runner.invoke(cli.app, ["menu"], input="2\n/tmp/example\n")
    assert result.exit_code == 0, result.output
    assert calls == [("/tmp/example", cli.RunFormat.HUMAN, False)]
    assert "Equivalent command: repoauditor run /tmp/example" in result.output


def test_finalize_menu_explains_review_block(tmp_config, monkeypatch):
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    state = MenuState((RepositoryState("r", "/repo", 2),))
    monkeypatch.setattr(cli, "load_menu_state", lambda config: state)
    monkeypatch.setattr(
        cli, "finalize", lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("blocked finalize must not run")
        ),
    )
    result = runner.invoke(cli.app, ["menu"], input="4\n1\n")
    assert result.exit_code == 0, result.output
    assert "Finalize is blocked: 2 review request(s) remain" in result.output


def test_doctor_menu_preserves_opt_in_live_check(tmp_config, monkeypatch):
    monkeypatch.setattr(cli, "get_config", lambda: tmp_config)
    calls = []
    monkeypatch.setattr(cli, "doctor", lambda model: calls.append(model))
    result = runner.invoke(cli.app, ["menu"], input="6\ny\n")
    assert result.exit_code == 0, result.output
    assert calls == [True]
    assert "repoauditor doctor --check-model" in result.output
