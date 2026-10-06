from __future__ import annotations

import json

import pytest

from crimson.aim_schemes import AimScheme
from crimson.game.loop_view import GameLoopView
from crimson.game_modes import GameMode
from crimson.leaderboard import Leaderboard
from crimson.modes.survival_mode import SurvivalMode
from crimson.quests.level import QUEST_COUNT
from crimson.replay.ranked import RANKED_VIEW
from crimson.screens.actions import ResultAction, Route, StartRun
from crimson.screens.assets import require_runtime_resources
from crimson.screens.panels import play_game
from crimson.screens.panels.play_game import PlayGameMenuView
from crimson.screens.results.game_over import GameOverUi
from grim import canvas
from grim.geom import Vec2
from grim.raylib_api import rl
from tests.screens.test_keyboard_journeys import press, tab_to
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


def _leaderboard(loop: GameLoopView, tmp_path, transport) -> Leaderboard:
    leaderboard = Leaderboard(tmp_path, url="https://crimson.test/api", transport=transport)
    loop.state.leaderboard = leaderboard
    return leaderboard


def _settle(leaderboard: Leaderboard) -> None:
    while leaderboard._pending:
        leaderboard._pending[0].result()
        leaderboard.drain()


def test_a_finished_ranked_run_queues_under_the_name_its_results_settle(loop, mocker, tmp_path) -> None:
    leaderboard = _leaderboard(loop, tmp_path, transport=mocker.Mock(side_effect=OSError("offline")))
    loop.state.config.profile.set_player_name_input("banteg")
    _click_ranked(loop, _play_game(loop), mocker)
    loop.navigation.navigate(StartRun(GameMode.SURVIVAL))
    run = loop.state.screens.gameplay
    assert isinstance(run, SurvivalMode)
    loop.update(1.0 / 60.0)
    run.player.health = 0.0
    run.player.death_timer = 0.0
    while not run._game_over_active:
        loop.update(1.0 / 60.0)
    assert leaderboard._held is not None

    mocker.patch.object(GameOverUi, "update", return_value=ResultAction.MAIN_MENU)
    loop.update(1.0 / 60.0)
    _settle(leaderboard)

    [queued] = (tmp_path / "leaderboard" / "outbox").glob("*.json")
    assert json.loads(queued.read_bytes())["name"] == "banteg"


def test_profile_shows_while_ranked_and_opens_the_signed_link(loop, mocker, tmp_path) -> None:
    answers = {"challenge": {"challenge": "c0ffee"}, "login": {"url": "https://crimson.test/login/once"}}
    _leaderboard(loop, tmp_path, transport=lambda url, _body: (200, answers[url.rsplit("/", 1)[1]]))
    opened = mocker.patch.object(play_game.webbrowser, "open")
    panel = _play_game(loop)
    assert not panel._profile_shown()

    _click_ranked(loop, panel, mocker)
    assert panel._profile_shown()
    assert panel._login is None, "ticking Ranked must not press Profile"
    button = panel._content_layout().base_pos + PlayGameMenuView._PROFILE_OFFSET
    mocker.patch.object(canvas, "mouse_position", return_value=(button + Vec2(20.0, 16.0)).to_rl())
    mocker.patch.object(rl, "is_mouse_button_pressed", return_value=True)
    loop.update(1.0 / 60.0)
    mocker.patch.object(rl, "is_mouse_button_pressed", return_value=False)
    assert panel._login is not None
    panel._login.result()
    loop.update(1.0 / 60.0)

    opened.assert_called_once_with("https://crimson.test/login/once")


def test_the_keyboard_reaches_profile_after_the_ranked_box(loop, mocker, tmp_path) -> None:
    leaderboard = _leaderboard(loop, tmp_path, transport=mocker.Mock(side_effect=OSError("offline")))
    panel = _play_game(loop)
    _click_ranked(loop, panel, mocker)
    mocker.patch.object(canvas, "mouse_position", return_value=rl.Vector2(0.0, 0.0))

    tab_to(loop, mocker, lambda: panel.profile_button.focused)
    press(loop, mocker, rl.KeyboardKey.KEY_ENTER)

    assert panel._login is not None
    with pytest.raises(OSError):
        panel._login.result()
    loop.update(1.0 / 60.0)
    assert panel._profile_note == "Can't reach the leaderboard."
    assert leaderboard.waiting == 0
