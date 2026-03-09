from __future__ import annotations

import time
from pathlib import Path

from crimson.game.loop_view import GameLoopView
from crimson.game.types import GameState
from crimson.modes.quest_mode import QuestMode
from crimson.modes.rush_mode import RushMode
from crimson.modes.survival_mode import SurvivalMode
from crimson.modes.tutorial_mode import TutorialMode
from crimson.modes.typo_mode import TypoShooterMode
from crimson.persistence import save_status
from crimson.screens.high_scores_view import HighScoresView
from crimson.screens.panels.network_session import NetworkSessionPanelView
from grim.config import ensure_crimson_cfg
from grim.console import create_console
from grim.rand import Crand


def test_start_actions_map_to_expected_views(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    assets_dir = repo_root / "artifacts" / "assets"

    cfg = ensure_crimson_cfg(tmp_path)
    state = GameState(
        base_dir=tmp_path,
        assets_dir=assets_dir,
        rng=Crand(0),
        config=cfg,
        status=save_status.ensure_game_status(tmp_path),
        console=create_console(tmp_path, assets_dir=assets_dir),
        demo_enabled=False,
        preserve_bugs=False,
        resources=None,
        audio=None,
        session_start=time.monotonic(),
    )

    loop = GameLoopView(state)
    start_survival = loop._front_route("start_survival")
    start_rush = loop._front_route("start_rush")
    start_typo = loop._front_route("start_typo")
    start_tutorial = loop._front_route("start_tutorial")
    start_quest = loop._front_route("start_quest")
    open_high_scores = loop._front_route("open_high_scores")
    open_lan_session = loop._front_route("open_lan_session")

    assert start_survival is not None
    assert start_rush is not None
    assert start_typo is not None
    assert start_tutorial is not None
    assert start_quest is not None
    assert open_high_scores is not None
    assert open_lan_session is not None

    assert isinstance(start_survival.view, SurvivalMode)
    assert isinstance(start_rush.view, RushMode)
    assert isinstance(start_typo.view, TypoShooterMode)
    assert isinstance(start_tutorial.view, TutorialMode)
    assert isinstance(start_quest.view, QuestMode)
    assert isinstance(open_high_scores.view, HighScoresView)
    assert isinstance(open_lan_session.view, NetworkSessionPanelView)
