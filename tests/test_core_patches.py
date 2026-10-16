"""Every crimson-core diff hunk still matches the recovered sources exactly once, without compiling anything."""

import importlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_every_hunk_matches_its_source_once(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.syspath_prepend(str(ROOT / "crimson-core"))
    adapter = importlib.import_module("adapter")
    # The game applies every verifier diff first, in the verifier's order, so its hunks cover both targets.
    game = importlib.import_module("game")

    if stale := adapter.stale_hunks(ROOT, adapter.load_diffs(game.GAME_DIFFS)):
        pytest.fail("\n".join(stale), pytrace=False)
