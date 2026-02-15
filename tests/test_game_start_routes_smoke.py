from __future__ import annotations

from pathlib import Path
import random
import time

from crimson.frontend.panels.lan_session import LanSessionPanelView
from crimson.game.high_scores_view import HighScoresView
from crimson.game.loop_view import GameLoopView
from crimson.game.mode_views import QuestGameView, RushGameView, SurvivalGameView, TutorialGameView, TypoShooterGameView
from crimson.game.types import GameState
from crimson.persistence import save_status
from grim.config import ensure_crimson_cfg
from grim.console import create_console


def test_start_actions_map_to_expected_views(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    cfg = ensure_crimson_cfg(tmp_path)
    state = GameState(
        base_dir=tmp_path,
        assets_dir=assets_dir,
        rng=random.Random(0),
        config=cfg,
        status=save_status.ensure_game_status(tmp_path),
        console=create_console(tmp_path, assets_dir=assets_dir),
        demo_enabled=False,
        preserve_bugs=False,
        logos=None,
        texture_cache=None,
        audio=None,
        resource_paq=assets_dir / "crimson.paq",
        session_start=time.monotonic(),
    )

    loop = GameLoopView(state)
    views = loop._front_views  # intentional: routing smoke test

    assert isinstance(views["start_survival"], SurvivalGameView)
    assert isinstance(views["start_rush"], RushGameView)
    assert isinstance(views["start_typo"], TypoShooterGameView)
    assert isinstance(views["start_tutorial"], TutorialGameView)
    assert isinstance(views["start_quest"], QuestGameView)
    assert isinstance(views["open_high_scores"], HighScoresView)
    assert isinstance(views["open_lan_session"], LanSessionPanelView)
