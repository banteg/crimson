from __future__ import annotations

import pytest

from crimson.game_modes import GameMode
from crimson.modes.tutorial_mode import TutorialMode
from crimson.perks import PerkId
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


def test_tutorial_stage6_pick_waits_for_sim_progress_before_reopen(mocker, make_mode_config, assets_dir) -> None:
    cfg = make_mode_config(game_mode=GameMode.TUTORIAL)
    mode = TutorialMode(ViewContext(assets_dir=assets_dir), config=cfg, audio_rng=Crand(0xBEEF))
    mode.open()

    mode.state.tutorial.stage_index = 6
    mode.state.perk_selection.pending_count = 1
    mode.state.perk_selection.choices[:] = [PerkId.GRIM_DEAL]
    mode.state.perk_selection.choices_dirty = False

    open_calls = 0
    original_open_perk_menu = mode._open_perk_menu

    def _counted_open() -> None:
        nonlocal open_calls
        open_calls += 1
        original_open_perk_menu()

    pick_calls = 0

    def _pick_once(_ctx, _choices, *, dt_ui_ms: float) -> int | None:
        nonlocal pick_calls
        _ = dt_ui_ms
        pick_calls += 1
        if pick_calls == 1:
            mode._perk_menu.close()
            return 0
        return None

    session = mode._sim_session
    assert session is not None

    tick_calls = 0

    def _run_ticks(**_kwargs) -> None:
        nonlocal tick_calls
        tick_calls += 1
        if tick_calls >= 2:
            # The queued pick applies on the first simulated tick.
            mode._live_ticks.next_tick()
            session.elapsed_ms += 1000.0 / 60.0

    mocker.patch.object(mode, "_open_perk_menu", side_effect=_counted_open)
    mocker.patch.object(mode._perk_menu, "handle_input", side_effect=_pick_once)
    mocker.patch.object(mode, "_run_deterministic_session_ticks", side_effect=_run_ticks)

    mode.update(1.0 / 60.0)
    assert open_calls == 1
    assert mode._perk_pick_pending is True

    mode._perk_menu.timeline_ms = 0.0
    mode.update(1.0 / 60.0)
    assert open_calls == 1
    assert mode._perk_pick_pending is False

    mode.update(1.0 / 60.0)
    assert open_calls == 2


def test_open_perk_menu_ignores_reopen_while_menu_active(mocker, make_mode_config, assets_dir) -> None:
    cfg = make_mode_config(game_mode=GameMode.TUTORIAL)
    mode = TutorialMode(ViewContext(assets_dir=assets_dir), config=cfg, audio_rng=Crand(0xBEEF))
    mode.open()

    mode._perk_menu.open = True

    record_checkpoint = mocker.patch.object(mode, "_record_replay_checkpoint")
    enqueue_command = mocker.patch.object(mode, "enqueue_input_command")

    mode._open_perk_menu()

    record_checkpoint.assert_not_called()
    enqueue_command.assert_not_called()
