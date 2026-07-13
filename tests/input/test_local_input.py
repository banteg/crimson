from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest
from pytest_mock import MockerFixture

from crimson import local_input
from crimson.aim_schemes import AimScheme
from crimson.game_modes import GameMode
from crimson.movement_controls import MovementControlType
from crimson.sim.state_types import PlayerState
from grim.config import CrimsonConfig, default_crimson_cfg
from grim.geom import Vec2
from tests.support.helpers import assert_float_close


class _DummyCreature:
    def __init__(self, *, pos: Vec2, active: bool = True, hp: float = 10.0) -> None:
        self.pos = pos
        self.active = active
        self.hp = hp


def _test_config(**updates: object) -> CrimsonConfig:
    cfg = default_crimson_cfg(Path("<memory>"))
    for key, value in updates.items():
        match str(key):
            case "player_count":
                cfg.gameplay.player_count = int(cast(Any, value))
            case "game_mode":
                cfg.gameplay.mode = GameMode(int(cast(Any, value)))
            case "fx_detail_0":
                cfg.display.set_fx_detail(0, bool(value))
            case _:
                raise KeyError(f"unsupported config update: {key}")
    return cfg


def _patch_keys_down(mocker: MockerFixture, *, down_codes: set[int]) -> None:
    mocker.patch.object(
        local_input,
        "input_code_is_down",
        lambda key, **_kwargs: int(key) in down_codes,
    )
    mocker.patch.object(local_input, "input_code_is_pressed", lambda *_args, **_kwargs: False)
    mocker.patch.object(local_input, "input_axis_value", lambda *_args, **_kwargs: 0.0)


def _patch_no_user_input(mocker: MockerFixture) -> None:
    mocker.patch.object(local_input, "input_code_is_down", lambda *_args, **_kwargs: False)
    mocker.patch.object(local_input, "input_code_is_pressed", lambda *_args, **_kwargs: False)
    mocker.patch.object(local_input, "input_axis_value", lambda *_args, **_kwargs: 0.0)


def _bind_values(values: list[int] | tuple[int, ...] | range) -> tuple[int, ...]:
    block = tuple(int(v) for v in values)
    if len(block) != 16:
        raise ValueError(f"expected 16 keybind values, got {len(block)}")
    return block


def _set_player_bind_values(
    cfg: CrimsonConfig,
    values: list[int] | tuple[int, ...] | range,
    *,
    player_index: int = 0,
) -> CrimsonConfig:
    block = _bind_values(values)
    player = cfg.controls.player(player_index)
    player.move_codes = (block[0], block[1], block[2], block[3])
    player.fire_code = block[4]
    player.keyboard_aim_codes = (block[7], block[8])
    player.aim_axis_codes = (block[9], block[10])
    player.move_axis_codes = (block[11], block[12])
    return cfg


def _set_player_modes(
    cfg: CrimsonConfig,
    *,
    aim_scheme: AimScheme | None = None,
    move_mode: MovementControlType | None = None,
    player_index: int = 0,
) -> CrimsonConfig:
    player = cfg.controls.player(player_index)
    if aim_scheme is not None:
        player.aim_scheme = aim_scheme
    if move_mode is not None:
        player.movement = move_mode
    return cfg


def _config_with_player_bind_values(
    values: list[int] | tuple[int, ...] | range,
    *,
    player_index: int = 0,
    player_count: int = 1,
    aim_scheme: AimScheme | None = None,
    move_mode: MovementControlType | None = None,
) -> CrimsonConfig:
    cfg = _test_config(player_count=player_count)
    _set_player_modes(cfg, aim_scheme=aim_scheme, move_mode=move_mode, player_index=player_index)
    return _set_player_bind_values(cfg, values, player_index=player_index)


def test_local_input_computer_aim_auto_fires_without_fire_pressed(mocker: MockerFixture) -> None:
    _patch_no_user_input(mocker)

    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), aim=Vec2(560.0, 512.0))
    creatures = [_DummyCreature(pos=Vec2(612.0, 512.0), active=True, hp=20.0)]
    config = _set_player_modes(_test_config(), aim_scheme=AimScheme.COMPUTER)

    out = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=config,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt=0.1,
        creatures=creatures,
    )

    assert out.fire_down is True
    assert out.fire_pressed is False
    assert_float_close(float(out.aim.x), 591.2)
    assert_float_close(float(out.aim.y), 512.0)


def test_local_input_computer_aim_without_target_points_away_from_center(mocker: MockerFixture) -> None:
    _patch_no_user_input(mocker)

    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), aim=Vec2(512.0, 512.0))
    config = _set_player_modes(_test_config(), aim_scheme=AimScheme.COMPUTER)

    out = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=config,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt=0.1,
        creatures=[],
    )

    assert out.fire_down is False
    assert out.fire_pressed is False
    assert_float_close(float(out.aim.x), 512.0)
    assert_float_close(float(out.aim.y), 452.0)


def test_local_input_computer_target_state_tracks_player_identity_not_call_slot(
    mocker: MockerFixture,
) -> None:
    _patch_no_user_input(mocker)

    interpreter = local_input.LocalInputInterpreter()
    player0 = PlayerState(index=0, pos=Vec2(0.0, 0.0), aim=Vec2(0.0, 0.0))
    player1 = PlayerState(index=1, pos=Vec2(128.0, 0.0), aim=Vec2(128.0, 0.0))
    config = _set_player_modes(_test_config(), aim_scheme=AimScheme.COMPUTER)
    creatures = [
        _DummyCreature(pos=Vec2(100.0, 0.0), active=True, hp=20.0),  # nearest to player0
        _DummyCreature(pos=Vec2(130.0, 0.0), active=True, hp=20.0),  # nearest to player1
    ]

    # Simulate a subset call where player1 is fed through slot 0 first.
    interpreter.build_player_input(
        player_index=0,
        player=player1,
        config=config,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt=0.1,
        creatures=creatures,
    )

    out = interpreter.build_player_input(
        player_index=0,
        player=player0,
        config=config,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt=0.1,
        creatures=creatures,
    )

    # Must track toward player0's nearest creature (x=100) not player1's target (x=130).
    assert_float_close(float(out.aim.x), 60.0)
    assert_float_close(float(out.aim.y), 0.0)


@pytest.mark.parametrize(
    ("down_codes", "expected_move"),
    (
        ({0, 1}, Vec2(0.0, 1.0)),  # Down overrides Up in native static mode.
        ({2, 3}, Vec2(1.0, 0.0)),  # Right overrides Left when no vertical key is active.
        ({0, 2, 3}, Vec2(-1.0, -1.0)),  # With Up held, Left wins diagonal tie.
    ),
)
def test_local_input_static_mode_conflict_precedence_matches_native(
    mocker: MockerFixture,
    down_codes: set[int],
    expected_move: Vec2,
) -> None:
    _patch_keys_down(mocker, down_codes=down_codes)

    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), aim=Vec2(160.0, 100.0))
    config = _config_with_player_bind_values(range(16))

    out = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=config,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt=0.1,
        creatures=[],
    )

    assert out.move == expected_move


def test_local_input_relative_mode_single_player_uses_alt_arrow_fallback(
    mocker: MockerFixture,
) -> None:
    _patch_keys_down(mocker, down_codes={0xC8, 0xCB})

    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), aim=Vec2(160.0, 100.0))
    config = _config_with_player_bind_values((0x17E,) * 16, move_mode=MovementControlType.RELATIVE)

    out = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=config,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt=0.1,
        creatures=[],
    )

    assert out.move_forward_pressed is True
    assert out.turn_left_pressed is True
    assert out.move == Vec2(-1.0, -1.0)


def test_local_input_relative_mode_multiplayer_does_not_use_alt_arrow_fallback(
    mocker: MockerFixture,
) -> None:
    _patch_keys_down(mocker, down_codes={0xC8, 0xCB})
    config = _config_with_player_bind_values((0x17E,) * 16, player_count=2, move_mode=MovementControlType.RELATIVE)

    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), aim=Vec2(160.0, 100.0))

    out = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=config,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt=0.1,
        creatures=[],
    )

    assert out.move_forward_pressed is False
    assert out.turn_left_pressed is False
    assert out.move == Vec2()


def test_local_input_reload_pressed_is_available_in_multiplayer(
    mocker: MockerFixture,
) -> None:
    _patch_no_user_input(mocker)
    mocker.patch.object(
        local_input,
        "input_code_is_pressed",
        lambda key, **_kwargs: int(key) == 0x102,
    )
    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), aim=Vec2(160.0, 100.0))

    single_player = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=_test_config(player_count=1),
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt=0.1,
        creatures=[],
    )
    multiplayer = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=_test_config(player_count=2),
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt=0.1,
        creatures=[],
    )

    assert single_player.reload_pressed is True
    assert multiplayer.reload_pressed is True


def test_local_input_reload_pressed_reads_per_player_input_slot(
    mocker: MockerFixture,
) -> None:
    _patch_no_user_input(mocker)
    mocker.patch.object(
        local_input,
        "input_code_is_pressed",
        lambda key, **kwargs: int(key) == 0x102 and int(kwargs.get("player_index", -1)) == 1,
    )
    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=1, pos=Vec2(100.0, 100.0), aim=Vec2(160.0, 100.0))

    out = interpreter.build_player_input(
        player_index=1,
        player=player,
        config=_test_config(player_count=2),
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt=0.1,
        creatures=[],
    )

    assert out.reload_pressed is True


def test_local_input_mouse_point_click_marks_move_to_cursor_press(
    mocker: MockerFixture,
) -> None:
    mouse_world = Vec2(160.0, 140.0)
    mocker.patch.object(
        local_input,
        "input_code_is_down",
        lambda key, **_kwargs: int(key) == 0x102,
    )
    mocker.patch.object(
        local_input,
        "input_code_is_pressed",
        lambda key, **_kwargs: int(key) == 0x102,
    )
    mocker.patch.object(local_input, "input_axis_value", lambda *_args, **_kwargs: 0.0)

    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), aim=Vec2(160.0, 100.0))
    config = _config_with_player_bind_values(range(16), move_mode=MovementControlType.MOUSE_POINT_CLICK)

    out = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=config,
        mouse_screen=Vec2(),
        mouse_world=mouse_world,
        screen_center=Vec2(),
        dt=0.1,
        creatures=[],
    )

    assert out.reload_pressed is True
    assert out.move_to_cursor_pressed is True
    assert interpreter._states[0].move_target == mouse_world
    expected, _distance = (mouse_world - player.pos).normalized_with_length()
    assert_float_close(float(out.move.x), float(expected.x))
    assert_float_close(float(out.move.y), float(expected.y))


def test_local_input_computer_move_mode_near_center_heads_toward_target(
    mocker: MockerFixture,
) -> None:
    _patch_no_user_input(mocker)

    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=0, pos=Vec2(500.0, 500.0), aim=Vec2(560.0, 500.0))
    creatures = [_DummyCreature(pos=Vec2(560.0, 500.0), active=True, hp=20.0)]
    config = _set_player_modes(_test_config(), move_mode=MovementControlType.COMPUTER)

    out = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=config,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt=0.1,
        creatures=creatures,
    )

    assert_float_close(float(out.move.x), 1.0)
    assert_float_close(float(out.move.y), 0.0)


def test_local_input_computer_move_mode_far_from_center_heads_toward_center(
    mocker: MockerFixture,
) -> None:
    _patch_no_user_input(mocker)

    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=0, pos=Vec2(900.0, 900.0), aim=Vec2(960.0, 900.0))
    creatures = [_DummyCreature(pos=Vec2(960.0, 900.0), active=True, hp=20.0)]
    config = _set_player_modes(_test_config(), move_mode=MovementControlType.COMPUTER)

    out = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=config,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt=0.1,
        creatures=creatures,
    )

    expected, _distance = (Vec2(512.0, 512.0) - player.pos).normalized_with_length()
    assert_float_close(float(out.move.x), float(expected.x))
    assert_float_close(float(out.move.y), float(expected.y))


def test_local_input_computer_aim_scheme_forces_computer_movement(
    mocker: MockerFixture,
) -> None:
    _patch_no_user_input(mocker)

    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=0, pos=Vec2(500.0, 500.0), aim=Vec2(560.0, 500.0))
    creatures = [_DummyCreature(pos=Vec2(560.0, 500.0), active=True, hp=20.0)]
    config = _set_player_modes(_test_config(), aim_scheme=AimScheme.COMPUTER)

    out = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=config,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt=0.1,
        creatures=creatures,
    )

    assert_float_close(float(out.move.x), 1.0)
    assert_float_close(float(out.move.y), 0.0)


def test_local_input_joystick_aim_uses_pov_not_aim_keybinds(
    mocker: MockerFixture,
) -> None:
    _patch_keys_down(mocker, down_codes={8})

    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), aim=Vec2(160.0, 100.0))
    config = _config_with_player_bind_values(range(16), aim_scheme=AimScheme.JOYSTICK)

    out = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=config,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt=0.1,
        creatures=[],
    )

    # Bound aim key 8 should not affect joystick aim scheme; only POV should.
    assert_float_close(float(out.aim.x), 100.0)
    assert_float_close(float(out.aim.y), 40.0)


def test_local_input_joystick_aim_turns_with_pov_input(
    mocker: MockerFixture,
) -> None:
    _patch_keys_down(mocker, down_codes={0x134})

    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), aim=Vec2(160.0, 100.0))
    config = _config_with_player_bind_values(range(16), aim_scheme=AimScheme.JOYSTICK)

    out = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=config,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt=0.1,
        creatures=[],
    )

    expected = player.pos + Vec2.from_heading(0.4) * 60.0
    assert_float_close(float(out.aim.x), float(expected.x))
    assert_float_close(float(out.aim.y), float(expected.y))


def test_local_input_joystick_aim_reads_player_pov_by_default(
    mocker: MockerFixture,
) -> None:
    mocker.patch.object(
        local_input,
        "input_code_is_down",
        lambda key, **kwargs: int(key) == 0x134 and int(kwargs.get("player_index", -1)) == 1,
    )
    mocker.patch.object(local_input, "input_code_is_pressed", lambda *_args, **_kwargs: False)
    mocker.patch.object(local_input, "input_axis_value", lambda *_args, **_kwargs: 0.0)

    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=1, pos=Vec2(100.0, 100.0), aim=Vec2(160.0, 100.0))
    config = _config_with_player_bind_values(
        range(16),
        player_index=1,
        player_count=2,
        aim_scheme=AimScheme.JOYSTICK,
    )

    out = interpreter.build_player_input(
        player_index=1,
        player=player,
        config=config,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt=0.1,
        creatures=[],
    )

    expected = player.pos + Vec2.from_heading(0.4) * 60.0
    assert_float_close(float(out.aim.x), float(expected.x))
    assert_float_close(float(out.aim.y), float(expected.y))


def test_local_input_joystick_aim_preserve_bugs_uses_player1_pov_slot(
    mocker: MockerFixture,
) -> None:
    mocker.patch.object(
        local_input,
        "input_code_is_down",
        lambda key, **kwargs: int(key) == 0x134 and int(kwargs.get("player_index", -1)) == 0,
    )
    mocker.patch.object(local_input, "input_code_is_pressed", lambda *_args, **_kwargs: False)
    mocker.patch.object(local_input, "input_axis_value", lambda *_args, **_kwargs: 0.0)

    interpreter = local_input.LocalInputInterpreter()
    interpreter.set_preserve_bugs(True)
    player = PlayerState(index=1, pos=Vec2(100.0, 100.0), aim=Vec2(160.0, 100.0))
    config = _config_with_player_bind_values(
        range(16),
        player_index=1,
        player_count=2,
        aim_scheme=AimScheme.JOYSTICK,
    )

    out = interpreter.build_player_input(
        player_index=1,
        player=player,
        config=config,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt=0.1,
        creatures=[],
    )

    expected = player.pos + Vec2.from_heading(0.4) * 60.0
    assert_float_close(float(out.aim.x), float(expected.x))
    assert_float_close(float(out.aim.y), float(expected.y))


def test_local_input_dual_action_pad_aim_uses_native_radius_scale(
    mocker: MockerFixture,
) -> None:
    mocker.patch.object(local_input, "input_code_is_down", lambda *_args, **_kwargs: False)
    mocker.patch.object(local_input, "input_code_is_pressed", lambda *_args, **_kwargs: False)
    mocker.patch.object(
        local_input,
        "input_axis_value",
        lambda key, **_kwargs: 1.0 if int(key) == 10 else 0.0,
    )

    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), aim=Vec2(160.0, 100.0))
    config = _config_with_player_bind_values(range(16), aim_scheme=AimScheme.DUAL_ACTION_PAD)

    out = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=config,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt=0.1,
        creatures=[],
    )

    # Native radius: 42 + mag * cv_padAimDistMul (default 96).
    assert_float_close(float(out.aim.x), 238.0)
    assert_float_close(float(out.aim.y), 100.0)


def test_local_input_keyboard_aim_in_static_mode_reanchors_to_heading(
    mocker: MockerFixture,
) -> None:
    _patch_no_user_input(mocker)

    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), aim=Vec2(180.0, 130.0), aim_heading=0.0)
    config = _config_with_player_bind_values(range(16), aim_scheme=AimScheme.KEYBOARD)

    out = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=config,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt=0.1,
        creatures=[],
    )

    assert_float_close(float(out.aim.x), 100.0)
    assert_float_close(float(out.aim.y), 40.0)


def test_local_input_keyboard_aim_with_non_relative_move_mode_keeps_world_aim(
    mocker: MockerFixture,
) -> None:
    _patch_no_user_input(mocker)

    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), aim=Vec2(180.0, 130.0), aim_heading=0.0)
    config = _config_with_player_bind_values(
        range(16),
        aim_scheme=AimScheme.KEYBOARD,
        move_mode=MovementControlType.DUAL_ACTION_PAD,
    )

    out = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=config,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt=0.1,
        creatures=[],
    )

    assert_float_close(float(out.aim.x), 180.0)
    assert_float_close(float(out.aim.y), 130.0)
    expected_heading = (player.aim - player.pos).to_heading()
    assert_float_close(float(interpreter._states[0].aim_heading), float(expected_heading))


def test_local_input_relative_mouse_aim_centered_keeps_world_aim(
    mocker: MockerFixture,
) -> None:
    _patch_no_user_input(mocker)

    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), aim=Vec2(180.0, 130.0), aim_heading=0.0)
    center = Vec2(320.0, 200.0)
    config = _config_with_player_bind_values(range(16), aim_scheme=AimScheme.MOUSE_RELATIVE)

    out = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=config,
        mouse_screen=center,
        mouse_world=Vec2(),
        screen_center=center,
        dt=0.1,
        creatures=[],
    )

    assert_float_close(float(out.aim.x), 180.0)
    assert_float_close(float(out.aim.y), 130.0)
    expected_heading = (player.aim - player.pos).to_heading()
    assert_float_close(float(interpreter._states[0].aim_heading), float(expected_heading))
