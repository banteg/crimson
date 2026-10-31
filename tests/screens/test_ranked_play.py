from __future__ import annotations

import json

import pytest

from crimson.aim_schemes import AimScheme
from crimson.cl_build import ClBuild
from crimson.game.loop_view import GameLoopView
from crimson.game_modes import GameMode
from crimson.leaderboard import Leaderboard
from crimson.modes.survival_mode import SurvivalMode
from crimson.quests.level import QUEST_COUNT
from crimson.replay.ranked import RANKED_VIEW, ranked_board, unranked_reasons
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


def _click(loop: GameLoopView, box: Vec2, mocker) -> None:
    mocker.patch.object(canvas, "mouse_position", return_value=(box + Vec2(4.0, 8.0)).to_rl())
    mocker.patch.object(rl, "is_mouse_button_pressed", return_value=True)
    loop.update(1.0 / 60.0)
    mocker.patch.object(rl, "is_mouse_button_pressed", return_value=False)


def _click_ranked(loop: GameLoopView, panel: PlayGameMenuView, mocker) -> None:
    _click(loop, panel._ranked_pos(panel._content_layout(), require_runtime_resources(loop.state)), mocker)


def _click_rules(loop: GameLoopView, panel: PlayGameMenuView, mocker) -> None:
    resources = require_runtime_resources(loop.state)
    _click(loop, panel._rules_pos(panel._ranked_pos(panel._content_layout(), resources), resources), mocker)


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


def test_the_1_9_8_box_and_ranked_tick_together(loop, mocker) -> None:
    state = loop.state
    state.config.profile.set_player_name_input("")
    panel = _play_game(loop)
    _click_ranked(loop, panel, mocker)

    _click_rules(loop, panel, mocker)

    assert (state.cl_build, state.ranked) == (ClBuild.V1_9_8, True)
    assert panel.ranked_checkbox.checked
    # A ranked 1.9.8 attempt lists the ranked modes, and its tip names 1.9.8's leaderboard.
    entries = panel._mode_entries()[0]
    assert [entry.key for entry in entries] == ["quests", "survival"]
    tips = dict(panel._port_tooltips(entries, require_runtime_resources(state).small_font))
    assert tips["ranked"] == "Play for the online 1.9.8 leaderboard."

    _click_rules(loop, panel, mocker)

    assert (state.cl_build, state.ranked) == (ClBuild.V1_9_93, True)


def test_a_ranked_1_9_8_attempt_plays_its_rules_on_the_ranked_profile(loop, mocker, tmp_path) -> None:
    leaderboard = _leaderboard(loop, tmp_path, transport=mocker.Mock(side_effect=OSError("offline")))
    state = loop.state
    state.config.gameplay.player_count = 2
    panel = _play_game(loop)
    _click_rules(loop, panel, mocker)
    _click_ranked(loop, panel, mocker)

    loop.navigation.navigate(StartRun(GameMode.SURVIVAL))

    run = state.screens.gameplay
    assert isinstance(run, SurvivalMode)
    assert run.ranked_run
    world = run.world
    assert world.state.rules_1_9_8
    assert len(world.players) == 1
    assert run.world_runtime.view_cap == RANKED_VIEW
    assert world.state.status is not state.status
    loop.update(1.0 / 60.0)
    run.player.health = 0.0
    run.player.death_timer = 0.0
    while not run._game_over_active:
        loop.update(1.0 / 60.0)
    held = leaderboard._held
    assert held is not None and held.run.cl_build == ClBuild.V1_9_8
    assert ranked_board(held.run) == "survival" and not unranked_reasons(held.run)


def test_an_unranked_1_9_8_run_plays_its_rules_on_the_players_own_team(loop, mocker, tmp_path) -> None:
    leaderboard = _leaderboard(loop, tmp_path, transport=mocker.Mock(side_effect=OSError("offline")))
    state = loop.state
    state.config.gameplay.player_count = 2
    _click_rules(loop, _play_game(loop), mocker)

    loop.navigation.navigate(StartRun(GameMode.SURVIVAL))

    run = state.screens.gameplay
    assert isinstance(run, SurvivalMode)
    assert not run.ranked_run
    world = run.world
    assert world.state.rules_1_9_8
    assert len(world.players) == 2
    assert run.world_runtime.view_cap != RANKED_VIEW
    assert run._replay_recorder is not None and run._replay_recorder.run.cl_build == ClBuild.V1_9_8
    loop.update(1.0 / 60.0)
    for player in world.players:
        player.health = 0.0
        player.death_timer = 0.0
    while not run._game_over_active:
        loop.update(1.0 / 60.0)
    assert leaderboard._held is None
    assert run._game_over_record is not None and run._game_over_record.cl_build == ClBuild.V1_9_8


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


def test_profile_opens_the_signed_link_without_ranked(loop, mocker, tmp_path) -> None:
    answers = {"challenge": {"challenge": "c0ffee"}, "login": {"url": "https://crimson.test/login/once"}}
    _leaderboard(loop, tmp_path, transport=lambda url, _body: (200, answers[url.rsplit("/", 1)[1]]))
    opened = mocker.patch.object(play_game.webbrowser, "open")
    panel = _play_game(loop)
    assert not panel.state.ranked
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
