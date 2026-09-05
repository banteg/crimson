from __future__ import annotations

import pytest

from crimson.game.loop_view import GameLoopView
from crimson.game_modes import GameMode
from crimson.modes.quest_mode import QuestMode
from crimson.modes.rush_mode import RushMode
from crimson.modes.survival_mode import SurvivalMode
from crimson.modes.tutorial_mode import TutorialMode
from crimson.modes.typo_mode import TypoShooterMode
from crimson.quests.level import QuestLevel
from crimson.screens.actions import StartRun


@pytest.mark.parametrize("mode_id", [GameMode.QUESTS, GameMode.TUTORIAL])
def test_lazy_demo_modes_construct_the_world_with_demo_settings(make_game_state, mode_id) -> None:
    state = make_game_state(demo_enabled=True)
    mode = GameLoopView(state).navigation._mode(mode_id)
    assert mode.demo_mode_active
    assert mode.sim_world.spawn_env.demo_mode_active
    assert mode.state.demo_mode_active


@pytest.mark.parametrize(
    ("mode_id", "mode_type"),
    [
        (GameMode.SURVIVAL, SurvivalMode),
        (GameMode.RUSH, RushMode),
        (GameMode.TYPO, TypoShooterMode),
        (GameMode.TUTORIAL, TutorialMode),
        (GameMode.QUESTS, QuestMode),
    ],
)
def test_start_requests_create_modes_on_first_entry(make_game_state, mocker, mode_id, mode_type) -> None:
    state = make_game_state()
    loop = GameLoopView(state)
    assert loop.navigation._modes == {}
    mocker.patch.object(mode_type, "open")
    mocker.patch.object(QuestMode, "start_run")
    level = QuestLevel(1, 1) if mode_id == GameMode.QUESTS else None
    request = StartRun.from_config(state.config, mode_id, quest_level=level)
    loop.navigation.navigate(request)
    mode = state.screens.active
    assert isinstance(mode, mode_type)
    assert state.screens.active_gameplay is mode
    assert list(loop.navigation._modes) == [mode_id]
    loop.navigation.navigate(request)
    assert state.screens.active is mode  # retain each mode's RNG history


def test_quest_retry_counter_flows_through_persistent_mode(make_game_state, mocker) -> None:
    state = make_game_state(quest_fail_retry_count=3)
    loop = GameLoopView(state)
    mode = loop.navigation._mode(GameMode.QUESTS)
    assert isinstance(mode, QuestMode)
    mocker.patch.object(mode, "open")
    start_run = mocker.patch.object(mode, "start_run")
    loop.navigation.navigate(StartRun.from_config(state.config, GameMode.QUESTS, quest_level=QuestLevel(1, 1)))
    assert mode.quest_fail_retry_count == 3
    start_run.assert_called_once_with(QuestLevel(1, 1), status=state.status)
    mode.sim_world.spawn_env.quest_fail_retry_count = 0
    assert loop._resolve_gameplay_action(mode, None) is None
    assert state.quest_fail_retry_count == 0
