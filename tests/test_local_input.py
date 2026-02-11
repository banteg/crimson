from __future__ import annotations

from types import SimpleNamespace

import pytest

from crimson import local_input
from crimson.gameplay import PlayerState
from crimson.movement_controls import MovementControlType
from grim.geom import Vec2


class _DummyCreature:
    def __init__(self, *, pos: Vec2, active: bool = True, hp: float = 10.0) -> None:
        self.pos = pos
        self.active = active
        self.hp = hp


def _patch_keys_down(monkeypatch: pytest.MonkeyPatch, *, down_codes: set[int]) -> None:
    monkeypatch.setattr(
        local_input,
        "input_code_is_down_for_player",
        lambda key, **_kwargs: int(key) in down_codes,
    )
    monkeypatch.setattr(local_input, "input_code_is_pressed_for_player", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(local_input, "input_axis_value_for_player", lambda *_args, **_kwargs: 0.0)


def _patch_no_user_input(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(local_input, "input_code_is_down_for_player", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(local_input, "input_code_is_pressed_for_player", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(local_input, "input_axis_value_for_player", lambda *_args, **_kwargs: 0.0)


def test_local_input_computer_aim_auto_fires_without_fire_pressed(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_no_user_input(monkeypatch)
    monkeypatch.setattr(
        local_input.LocalInputInterpreter,
        "_safe_controls_modes",
        staticmethod(lambda _config, *, player_index: (5, MovementControlType.STATIC)),
    )

    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), aim=Vec2(560.0, 512.0))
    creatures = [_DummyCreature(pos=Vec2(612.0, 512.0), active=True, hp=20.0)]

    out = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=None,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt_frame=0.1,
        creatures=creatures,
    )

    assert out.fire_down is True
    assert out.fire_pressed is False
    assert float(out.aim.x) == pytest.approx(591.2, abs=1e-4)
    assert float(out.aim.y) == pytest.approx(512.0, abs=1e-4)


def test_local_input_computer_aim_without_target_points_away_from_center(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_no_user_input(monkeypatch)
    monkeypatch.setattr(
        local_input.LocalInputInterpreter,
        "_safe_controls_modes",
        staticmethod(lambda _config, *, player_index: (5, MovementControlType.STATIC)),
    )

    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0), aim=Vec2(512.0, 512.0))

    out = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=None,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt_frame=0.1,
        creatures=[],
    )

    assert out.fire_down is False
    assert out.fire_pressed is False
    assert float(out.aim.x) == pytest.approx(512.0, abs=1e-6)
    assert float(out.aim.y) == pytest.approx(452.0, abs=1e-6)


@pytest.mark.parametrize(
    ("down_codes", "expected_move"),
    (
        ({0, 1}, Vec2(0.0, 1.0)),  # Down overrides Up in native static mode.
        ({2, 3}, Vec2(1.0, 0.0)),  # Right overrides Left when no vertical key is active.
        ({0, 2, 3}, Vec2(-1.0, -1.0)),  # With Up held, Left wins diagonal tie.
    ),
)
def test_local_input_static_mode_conflict_precedence_matches_native(
    monkeypatch: pytest.MonkeyPatch,
    down_codes: set[int],
    expected_move: Vec2,
) -> None:
    _patch_keys_down(monkeypatch, down_codes=down_codes)
    monkeypatch.setattr(
        local_input,
        "_load_player_bind_block",
        lambda _config, *, player_index: tuple(range(16)),
    )
    monkeypatch.setattr(
        local_input.LocalInputInterpreter,
        "_safe_controls_modes",
        staticmethod(lambda _config, *, player_index: (0, MovementControlType.STATIC)),
    )

    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), aim=Vec2(160.0, 100.0))

    out = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=None,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt_frame=0.1,
        creatures=[],
    )

    assert out.move == expected_move


def test_local_input_relative_mode_single_player_uses_alt_arrow_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_keys_down(monkeypatch, down_codes={0xC8, 0xCB})
    monkeypatch.setattr(
        local_input,
        "_load_player_bind_block",
        lambda _config, *, player_index: (0x17E,) * 16,
    )
    monkeypatch.setattr(
        local_input.LocalInputInterpreter,
        "_safe_controls_modes",
        staticmethod(lambda _config, *, player_index: (0, MovementControlType.RELATIVE)),
    )

    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), aim=Vec2(160.0, 100.0))

    out = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=None,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt_frame=0.1,
        creatures=[],
    )

    assert out.move_forward_pressed is True
    assert out.turn_left_pressed is True
    assert out.move == Vec2(-1.0, -1.0)


def test_local_input_relative_mode_multiplayer_does_not_use_alt_arrow_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_keys_down(monkeypatch, down_codes={0xC8, 0xCB})
    monkeypatch.setattr(
        local_input,
        "_load_player_bind_block",
        lambda _config, *, player_index: (0x17E,) * 16,
    )
    monkeypatch.setattr(
        local_input.LocalInputInterpreter,
        "_safe_controls_modes",
        staticmethod(lambda _config, *, player_index: (0, MovementControlType.RELATIVE)),
    )
    config = SimpleNamespace(data={"player_count": 2})

    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), aim=Vec2(160.0, 100.0))

    out = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=config,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt_frame=0.1,
        creatures=[],
    )

    assert out.move_forward_pressed is False
    assert out.turn_left_pressed is False
    assert out.move == Vec2()


def test_local_input_computer_move_mode_near_center_heads_toward_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_no_user_input(monkeypatch)
    monkeypatch.setattr(
        local_input.LocalInputInterpreter,
        "_safe_controls_modes",
        staticmethod(lambda _config, *, player_index: (0, MovementControlType.COMPUTER)),
    )

    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=0, pos=Vec2(500.0, 500.0), aim=Vec2(560.0, 500.0))
    creatures = [_DummyCreature(pos=Vec2(560.0, 500.0), active=True, hp=20.0)]

    out = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=None,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt_frame=0.1,
        creatures=creatures,
    )

    assert float(out.move.x) == pytest.approx(1.0, abs=1e-6)
    assert float(out.move.y) == pytest.approx(0.0, abs=1e-6)


def test_local_input_computer_move_mode_far_from_center_heads_toward_center(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_no_user_input(monkeypatch)
    monkeypatch.setattr(
        local_input.LocalInputInterpreter,
        "_safe_controls_modes",
        staticmethod(lambda _config, *, player_index: (0, MovementControlType.COMPUTER)),
    )

    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=0, pos=Vec2(900.0, 900.0), aim=Vec2(960.0, 900.0))
    creatures = [_DummyCreature(pos=Vec2(960.0, 900.0), active=True, hp=20.0)]

    out = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=None,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt_frame=0.1,
        creatures=creatures,
    )

    expected = (Vec2(512.0, 512.0) - player.pos).normalized()
    assert float(out.move.x) == pytest.approx(float(expected.x), abs=1e-6)
    assert float(out.move.y) == pytest.approx(float(expected.y), abs=1e-6)


def test_local_input_computer_aim_scheme_forces_computer_movement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_no_user_input(monkeypatch)
    monkeypatch.setattr(
        local_input.LocalInputInterpreter,
        "_safe_controls_modes",
        staticmethod(lambda _config, *, player_index: (5, MovementControlType.STATIC)),
    )

    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=0, pos=Vec2(500.0, 500.0), aim=Vec2(560.0, 500.0))
    creatures = [_DummyCreature(pos=Vec2(560.0, 500.0), active=True, hp=20.0)]

    out = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=None,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt_frame=0.1,
        creatures=creatures,
    )

    assert float(out.move.x) == pytest.approx(1.0, abs=1e-6)
    assert float(out.move.y) == pytest.approx(0.0, abs=1e-6)


def test_local_input_joystick_aim_uses_pov_not_aim_keybinds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_keys_down(monkeypatch, down_codes={8})
    monkeypatch.setattr(
        local_input,
        "_load_player_bind_block",
        lambda _config, *, player_index: tuple(range(16)),
    )
    monkeypatch.setattr(
        local_input.LocalInputInterpreter,
        "_safe_controls_modes",
        staticmethod(lambda _config, *, player_index: (2, MovementControlType.STATIC)),
    )

    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), aim=Vec2(160.0, 100.0))

    out = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=None,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt_frame=0.1,
        creatures=[],
    )

    # Bound aim key 8 should not affect joystick aim scheme; only POV should.
    assert float(out.aim.x) == pytest.approx(100.0, abs=1e-6)
    assert float(out.aim.y) == pytest.approx(40.0, abs=1e-6)


def test_local_input_joystick_aim_turns_with_pov_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_keys_down(monkeypatch, down_codes={0x134})
    monkeypatch.setattr(
        local_input,
        "_load_player_bind_block",
        lambda _config, *, player_index: tuple(range(16)),
    )
    monkeypatch.setattr(
        local_input.LocalInputInterpreter,
        "_safe_controls_modes",
        staticmethod(lambda _config, *, player_index: (2, MovementControlType.STATIC)),
    )

    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), aim=Vec2(160.0, 100.0))

    out = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=None,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt_frame=0.1,
        creatures=[],
    )

    expected = player.pos + Vec2.from_heading(0.4) * 60.0
    assert float(out.aim.x) == pytest.approx(float(expected.x), abs=1e-6)
    assert float(out.aim.y) == pytest.approx(float(expected.y), abs=1e-6)


def test_local_input_dual_action_pad_aim_uses_native_radius_scale(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(local_input, "input_code_is_down_for_player", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(local_input, "input_code_is_pressed_for_player", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(
        local_input,
        "input_axis_value_for_player",
        lambda key, **_kwargs: 1.0 if int(key) == 10 else 0.0,
    )
    monkeypatch.setattr(
        local_input,
        "_load_player_bind_block",
        lambda _config, *, player_index: tuple(range(16)),
    )
    monkeypatch.setattr(
        local_input.LocalInputInterpreter,
        "_safe_controls_modes",
        staticmethod(lambda _config, *, player_index: (4, MovementControlType.STATIC)),
    )

    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), aim=Vec2(160.0, 100.0))

    out = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=None,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt_frame=0.1,
        creatures=[],
    )

    # Native radius: 42 + mag * cv_padAimDistMul (default 96).
    assert float(out.aim.x) == pytest.approx(238.0, abs=1e-6)
    assert float(out.aim.y) == pytest.approx(100.0, abs=1e-6)


def test_local_input_keyboard_aim_in_static_mode_reanchors_to_heading(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_no_user_input(monkeypatch)
    monkeypatch.setattr(
        local_input,
        "_load_player_bind_block",
        lambda _config, *, player_index: tuple(range(16)),
    )
    monkeypatch.setattr(
        local_input.LocalInputInterpreter,
        "_safe_controls_modes",
        staticmethod(lambda _config, *, player_index: (1, MovementControlType.STATIC)),
    )

    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), aim=Vec2(180.0, 130.0), aim_heading=0.0)

    out = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=None,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt_frame=0.1,
        creatures=[],
    )

    assert float(out.aim.x) == pytest.approx(100.0, abs=1e-6)
    assert float(out.aim.y) == pytest.approx(40.0, abs=1e-6)


def test_local_input_keyboard_aim_with_non_relative_move_mode_keeps_world_aim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_no_user_input(monkeypatch)
    monkeypatch.setattr(
        local_input,
        "_load_player_bind_block",
        lambda _config, *, player_index: tuple(range(16)),
    )
    monkeypatch.setattr(
        local_input.LocalInputInterpreter,
        "_safe_controls_modes",
        staticmethod(lambda _config, *, player_index: (1, MovementControlType.DUAL_ACTION_PAD)),
    )

    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), aim=Vec2(180.0, 130.0), aim_heading=0.0)

    out = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=None,
        mouse_screen=Vec2(),
        mouse_world=Vec2(),
        screen_center=Vec2(),
        dt_frame=0.1,
        creatures=[],
    )

    assert float(out.aim.x) == pytest.approx(180.0, abs=1e-6)
    assert float(out.aim.y) == pytest.approx(130.0, abs=1e-6)
    expected_heading = (player.aim - player.pos).to_heading()
    assert float(interpreter._states[0].aim_heading) == pytest.approx(float(expected_heading), abs=1e-6)


def test_local_input_relative_mouse_aim_centered_keeps_world_aim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_no_user_input(monkeypatch)
    monkeypatch.setattr(
        local_input,
        "_load_player_bind_block",
        lambda _config, *, player_index: tuple(range(16)),
    )
    monkeypatch.setattr(
        local_input.LocalInputInterpreter,
        "_safe_controls_modes",
        staticmethod(lambda _config, *, player_index: (3, MovementControlType.STATIC)),
    )

    interpreter = local_input.LocalInputInterpreter()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), aim=Vec2(180.0, 130.0), aim_heading=0.0)
    center = Vec2(320.0, 200.0)

    out = interpreter.build_player_input(
        player_index=0,
        player=player,
        config=None,
        mouse_screen=center,
        mouse_world=Vec2(),
        screen_center=center,
        dt_frame=0.1,
        creatures=[],
    )

    assert float(out.aim.x) == pytest.approx(180.0, abs=1e-6)
    assert float(out.aim.y) == pytest.approx(130.0, abs=1e-6)
    expected_heading = (player.aim - player.pos).to_heading()
    assert float(interpreter._states[0].aim_heading) == pytest.approx(float(expected_heading), abs=1e-6)
