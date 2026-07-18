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
from crimson.quests.level import QuestLevel
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
    views = loop._front_views  # intentional: routing smoke test

    assert isinstance(views["start_survival"], SurvivalMode)
    assert isinstance(views["start_rush"], RushMode)
    assert isinstance(views["start_typo"], TypoShooterMode)
    assert isinstance(views["start_tutorial"], TutorialMode)
    assert isinstance(views["start_quest"], QuestMode)
    assert isinstance(views["open_high_scores"], HighScoresView)
    assert isinstance(views["open_lan_session"], NetworkSessionPanelView)


def test_quest_retry_counter_flows_through_persistent_mode(make_game_state, mocker) -> None:
    state = make_game_state(quest_fail_retry_count=3)
    state.pending_quest_level = QuestLevel(1, 1)
    loop = GameLoopView(state)
    mode = loop._front_views["start_quest"]
    assert isinstance(mode, QuestMode)
    start_run = mocker.patch.object(mode, "start_run")

    loop._prepare_quest_run(mode)

    assert mode.quest_fail_retry_count == 3
    start_run.assert_called_once_with(QuestLevel(1, 1), status=state.status)

    # A hardcore spawn clears the simulation's shared counter. The regular
    # gameplay-action resolution pass must publish that value back to the
    # failed-screen owner before it chooses the next view.
    mode.sim_world.spawn_env.quest_fail_retry_count = 0
    assert loop._resolve_gameplay_action(mode, None) is None
    assert state.quest_fail_retry_count == 0
