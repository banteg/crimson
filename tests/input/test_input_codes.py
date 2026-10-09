from __future__ import annotations

import pytest

from crimson import input_codes
from crimson.game_modes import GameMode
from crimson.local_input import LocalInputInterpreter
from crimson.replay.input_codec import unpack_player_input
from crimson.replay.ticks import LiveTickSource, step_replay_tick
from crimson.sim.input import PlayerInput
from crimson.sim.run_init import initialize_run
from crimson.sim.run_spec import RunSpec
from grim.config import default_crimson_cfg
from grim.geom import Vec2


def test_axis_z_and_rot_x_bindings_use_distinct_raylib_axes() -> None:
    assert input_codes._AXIS_CODE_TO_AXIS[0x141] != input_codes._AXIS_CODE_TO_AXIS[0x153]


def test_pressed_edge_does_not_retrigger_after_unpolled_held_frame(mocker) -> None:
    key_down = {"value": False}

    mocker.patch.object(input_codes.rl, "is_key_down", side_effect=lambda _key: bool(key_down["value"]))
    mocker.patch.object(input_codes.rl, "get_mouse_wheel_move", return_value=0.0)

    input_codes._PRESSED_STATE.prev_down.clear()
    input_codes._PRESSED_STATE.down.clear()
    input_codes._PRESSED_STATE.pressed_cache.clear()
    input_codes._PRESSED_STATE.wheel_up = False
    input_codes._PRESSED_STATE.wheel_down = False

    input_codes.input_begin_frame()
    key_down["value"] = True
    assert input_codes.input_code_is_pressed(0x11, player_index=0)

    input_codes.input_begin_frame()
    # Simulate a frame where this binding is not queried at all.
    input_codes.input_begin_frame()

    assert not input_codes.input_code_is_pressed(0x11, player_index=0)


def test_input_primary_just_pressed_latches_across_multiplayer_fire_keys(mocker) -> None:
    down: dict[tuple[int, int], bool] = {}
    fire_codes = (0x100, 0x9D, 0x36, 0x11F)

    def _fake_input_code_is_down(key_code: int, *, player_index: int = 0) -> bool:
        return bool(down.get((int(player_index), int(key_code)), False))

    mocker.patch.object(input_codes, "input_code_is_down", side_effect=_fake_input_code_is_down)
    mocker.patch.object(input_codes.rl, "get_mouse_wheel_move", return_value=0.0)

    input_codes._PRESSED_STATE.prev_down.clear()
    input_codes._PRESSED_STATE.down.clear()
    input_codes._PRESSED_STATE.pressed_cache.clear()
    input_codes._PRESSED_STATE.wheel_up = False
    input_codes._PRESSED_STATE.wheel_down = False

    # Player 2 fire key press opens the latch in two-player mode.
    input_codes.input_begin_frame()
    down[(1, 0x9D)] = True
    assert input_codes.input_primary_just_pressed(fire_codes=fire_codes, player_count=2)

    # Holding any primary source should not retrigger next frame.
    input_codes.input_begin_frame()
    assert not input_codes.input_primary_just_pressed(fire_codes=fire_codes, player_count=2)

    # Pressing another primary source while already held still does not retrigger.
    input_codes.input_begin_frame()
    down[(0, 0x100)] = True
    assert not input_codes.input_primary_just_pressed(fire_codes=fire_codes, player_count=2)

    # Releasing all sources clears the latch.
    input_codes.input_begin_frame()
    down[(1, 0x9D)] = False
    down[(0, 0x100)] = False
    assert not input_codes.input_primary_just_pressed(fire_codes=fire_codes, player_count=2)

    # Fresh primary press edges again after full release.
    input_codes.input_begin_frame()
    down[(0, 0x100)] = True
    assert input_codes.input_primary_just_pressed(fire_codes=fire_codes, player_count=2)


@pytest.mark.parametrize("wheel", [1.0, -1.0])
@pytest.mark.parametrize("zero_tick_frames", [0, 3])
def test_wheel_fire_binding_reaches_exactly_one_simulation_tick(mocker, wheel: float, zero_tick_frames: int) -> None:
    mocker.patch.object(input_codes, "_PRESSED_STATE", input_codes._PressedState())
    wheel_move = mocker.patch.object(input_codes.rl, "get_mouse_wheel_move", return_value=wheel)
    mocker.patch.object(input_codes.rl, "get_key_pressed", return_value=0)
    mocker.patch.object(input_codes.rl, "is_mouse_button_pressed", return_value=False)
    mocker.patch.object(input_codes.rl, "is_key_down", return_value=False)
    mocker.patch.object(input_codes.rl, "is_mouse_button_down", return_value=False)
    input_codes.input_begin_frame()
    code = input_codes.capture_first_pressed_input_code(player_index=0, include_gamepad=False, include_axes=False)
    assert code == (0x109 if wheel > 0 else 0x10A)
    config = default_crimson_cfg()
    config.controls.player(0).fire_code = code
    session = initialize_run(RunSpec(game_mode_id=GameMode.TUTORIAL, seed=1)).session
    interpreter = LocalInputInterpreter()

    def sample() -> PlayerInput:
        return interpreter.build_player_input(
            player_index=0, player=session.world.players[0], config=config,
            mouse_screen=Vec2(600, 512), mouse_world=Vec2(600, 512),
        )

    ticks = LiveTickSource()
    ticks.poll([sample()])
    wheel_move.return_value = 0.0
    for _ in range(zero_tick_frames):
        input_codes.input_begin_frame()
        ticks.poll([sample()])
    for index in range(30):
        tick = ticks.next_tick()
        assert unpack_player_input(tick.inputs[0]).fire_down is (index == 0)
        step_replay_tick(session, tick)
    assert session.world.state.shots_fired == 1


@pytest.mark.parametrize(
    ("key", "code"),
    [
        (input_codes.rl.KeyboardKey.KEY_KP_7, 0x47),
        (input_codes.rl.KeyboardKey.KEY_KP_ADD, 0x4E),
        (input_codes.rl.KeyboardKey.KEY_KP_ENTER, 0x9C),
        (input_codes.rl.KeyboardKey.KEY_RIGHT_ALT, 0xB8),
    ],
)
def test_numpad_and_right_alt_can_be_bound(mocker, key: int, code: int) -> None:
    # Native binds any DIK code; the capture used to drop keys the port had no mapping for.
    keys = iter((int(key), 0))
    mocker.patch.object(input_codes.rl, "get_key_pressed", side_effect=lambda: next(keys))
    assert input_codes.capture_first_pressed_input_code(player_index=0, include_mouse=False, include_gamepad=False) == code
    mocker.patch.object(input_codes.rl, "is_key_down", side_effect=lambda k: k == int(key))
    assert input_codes.input_code_is_down(code)
