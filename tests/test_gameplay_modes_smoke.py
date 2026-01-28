from __future__ import annotations

from pathlib import Path

from crimson.modes.base_gameplay_mode import BaseGameplayMode
from crimson.modes.rush_mode import RushMode
from crimson.modes.survival_mode import SurvivalMode
from grim.view import ViewContext


def test_modes_construct_without_window() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    ctx = ViewContext(assets_dir=repo_root / "artifacts" / "assets")

    assert isinstance(SurvivalMode(ctx), BaseGameplayMode)
    assert isinstance(RushMode(ctx), BaseGameplayMode)

