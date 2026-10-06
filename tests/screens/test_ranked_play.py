from __future__ import annotations

from crimson.aim_schemes import AimScheme
from crimson.game.loop_view import GameLoopView
from crimson.game_modes import GameMode
from crimson.modes.survival_mode import SurvivalMode
from crimson.quests.level import QUEST_COUNT
from crimson.replay.ranked import RANKED_VIEW
from crimson.screens.actions import Route, StartRun
from crimson.screens.assets import require_runtime_resources
from crimson.screens.panels.play_game import PlayGameMenuView
from grim import canvas
from grim.geom import Vec2
from grim.raylib_api import rl
from tests.support.screens import finish_transition


def _play_game(loop: GameLoopView) -> PlayGameMenuView:
    loop.navigation.navigate(Route.PLAY_GAME)
    finish_transition(loop)
    panel = loop.state.screens.active
    assert isinstance(panel, PlayGameMenuView)
    return panel


def _click_ranked(loop: GameLoopView, panel: PlayGameMenuView, mocker) -> None:
    box = panel._ranked_pos(panel._content_layout(), require_runtime_resources(loop.state)) + Vec2(4.0, 8.0)
    mocker.patch.object(canvas, "mouse_position", return_value=box.to_rl())
    mocker.patch.object(rl, "is_mouse_button_pressed", return_value=True)
    loop.update(1.0 / 60.0)
    mocker.patch.object(rl, "is_mouse_button_pressed", return_value=False)


def test_a_ranked_attempt_plays_the_ranked_profile(loop, mocker) -> None:
    state = loop.state
    state.config.gameplay.player_count = 3
    panel = _play_game(loop)

    _click_ranked(loop, panel, mocker)

    assert state.ranked
    assert state.config.gameplay.player_count == 1
    assert [entry.key for entry in panel._mode_entries()[0]] == ["quests", "survival"]

    loop.navigation.navigate(StartRun(GameMode.SURVIVAL))
    run = state.screens.gameplay
    assert isinstance(run, SurvivalMode)
    assert run.ranked_run
    world = run.world
    assert len(world.players) == 1
    assert (world.state.status.quest_unlock_index, world.state.status.quest_unlock_index_hardcore) == (QUEST_COUNT, QUEST_COUNT)
    assert not any(world.state.status.weapon_usage_counts)
    assert world.state.detail_preset == 5
    assert not world.state.preserve_bugs
    assert run.world_runtime.view_cap == RANKED_VIEW
    # The player's own save is untouched by the run.
    assert world.state.status is not state.status


def test_computer_controls_turn_ranked_off(loop, mocker) -> None:
    state = loop.state
    panel = _play_game(loop)
    _click_ranked(loop, panel, mocker)
    assert state.ranked

    state.config.controls.player(0).aim_scheme = AimScheme.COMPUTER
    loop.update(1.0 / 60.0)

    assert not state.ranked
    assert panel.ranked_checkbox.disabled
