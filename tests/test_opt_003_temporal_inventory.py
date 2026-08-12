"""OPT-003 aggregate inventory measurement never selects or exposes candidates."""

from __future__ import annotations

import inspect

from repoauditor.eval import temporal_inventory


def test_inventory_binds_three_wave_two_sources_and_runs():
    sources = temporal_inventory.SOURCES
    assert len(sources) == 3
    assert {item["run"] for item in sources.values()} == {39, 40, 41}
    assert len({item["family"] for item in sources.values()}) == 3
    assert all(len(item["commit"]) == 40 for item in sources.values())


def test_inventory_is_aggregate_only_and_score_blind():
    source = inspect.getsource(temporal_inventory.measure)
    assert "p_actionable" not in source
    assert "rank" not in source
    assert "suppressed" not in source
    assert "candidate_identities_disclosed" in source
    assert '"entries"' not in source


def test_inventory_requires_six_per_family_and_eighteen_total():
    source = inspect.getsource(temporal_inventory.measure)
    assert '"minimum_required": 6' in source
    assert '"minimum_total_required": 18' in source
