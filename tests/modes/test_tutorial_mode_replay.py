from __future__ import annotations

import pytest

from crimson.game_modes import GameMode
from crimson.modes.components import perk_prompt_controller
from crimson.modes.tutorial_mode import TutorialMode
from crimson.replay.driver.playback_driver import PlaybackDriver
from crimson.replay.input_codec import pack_tick
from crimson.sim.input import PlayerInput
from crimson.sim.sessions import DeterministicSession
from grim.geom import Vec2
from grim.rand import Crand
from grim.view import ViewContext
from tests.support.replay_runner_helpers import unverified_replay

pytestmark = pytest.mark.usefixtures("headless_resources")


def test_tutorial_constructor_starts_without_placeholder_session(make_mode_config, assets_dir) -> None:
    config = make_mode_config(game_mode=GameMode.TUTORIAL)
    mode = TutorialMode(ViewContext(assets_dir=assets_dir), config=config, audio_rng=Crand(0xBEEF))
    assert mode._sim_session is None


def test_tutorial_open_creates_session_and_recorder(mocker, make_mode_config, assets_dir) -> None:
    cfg = make_mode_config(game_mode=GameMode.TUTORIAL, updates={"player_count": 4})
    mode = TutorialMode(ViewContext(assets_dir=assets_dir), config=cfg, audio_rng=Crand(0xBEEF))
    reset_runtime = mocker.spy(mode._world_runtime, "reset")
    mode.open()

    assert int(mode.config.gameplay.player_count) == 4
    assert reset_runtime.call_args.kwargs["player_count"] == 1
    assert isinstance(mode._sim_session, DeterministicSession)
    assert mode._replay_recorder is not None
    assert mode._replay_recorder.run.game_mode_id == GameMode.TUTORIAL
    assert int(mode._replay_recorder.run.player_count) == 1


def test_tutorial_recorded_first_shot_replays_the_live_startup(make_mode_config, assets_dir) -> None:
    mode = TutorialMode(
        ViewContext(assets_dir=assets_dir),
        config=make_mode_config(game_mode=GameMode.TUTORIAL),
        audio_rng=Crand(0xBEEF),
    )
    mode.open()
    session = mode._sim_session
    recorder = mode._replay_recorder
    assert session is not None and recorder is not None
    inputs = (PlayerInput(aim=Vec2(600.0, 512.0), fire_down=True, fire_pressed=True),)
    recorder.record(pack_tick(inputs))
    driver = PlaybackDriver(unverified_replay(recorder))
    assert session.world.players == driver.world.players

    live_tick = session.step_tick(dt=1 / 60, inputs=inputs)
    replay_tick = driver.step_tick(0).payload

    assert session.world.players[0].shot_seq == 1
    assert session.world.players == driver.world.players
    assert session.world.state.rng.state == driver.world.state.rng.state
    assert live_tick.presentation == replay_tick.presentation


def test_tutorial_perk_menu_opens_from_the_level_up_prompt(mocker, make_mode_config, assets_dir) -> None:
    # Native has no tutorial auto-open: stage 6 asks the player to click the level-up sign.
    mode = TutorialMode(
        ViewContext(assets_dir=assets_dir),
        config=make_mode_config(game_mode=GameMode.TUTORIAL),
        audio_rng=Crand(0xBEEF),
    )
    mode.open()
    mode.state.tutorial.stage_index = 6
    mode.state.perk_selection.pending_count = 1

    for _ in range(30):
        mode.update(1.0 / 60.0)
    assert not mode._perk_menu.active
    assert mode._perk_prompt.timer_ms > 0.0

    pick_key = mode.config.controls.pick_perk_code
    mocker.patch.object(
        perk_prompt_controller,
        "input_code_is_pressed",
        side_effect=lambda code, player_index=0: code == pick_key,
    )
    mode.update(1.0 / 60.0)
    assert mode._perk_menu.open


def test_request_perk_menu_ignores_reopen_while_menu_active(mocker, make_mode_config, assets_dir) -> None:
    cfg = make_mode_config(game_mode=GameMode.TUTORIAL)
    mode = TutorialMode(ViewContext(assets_dir=assets_dir), config=cfg, audio_rng=Crand(0xBEEF))
    mode.open()

    mode._perk_menu.open = True

    enqueue_command = mocker.patch.object(mode, "enqueue_input_command")

    mode._request_perk_menu()

    enqueue_command.assert_not_called()
