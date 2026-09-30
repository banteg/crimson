import struct
from pathlib import Path

import msgspec
import pytest

from crimson import local_input
from crimson.aim_schemes import AimScheme
from crimson.gameplay import _player_update_aim_by_scheme
from crimson.math_parity import native_aim_point_from_heading
from crimson.movement_controls import MovementControlType
from crimson.sim.state_types import PlayerState
from grim.config import default_crimson_cfg
from grim.geom import Vec2
from tests.support.factories import player_input


class _Witness(msgspec.Struct, frozen=True):
    position_x: float
    position_y: float
    heading: float
    aim_x_bits: int
    aim_y_bits: int


class _Witnesses(msgspec.Struct, frozen=True):
    witnesses: list[_Witness]


def _witnesses() -> list[_Witness]:
    path = Path(__file__).resolve().parents[2] / "crimson-zig/src/runtime/testdata/player-aim-point.json"
    rows = msgspec.json.decode(path.read_bytes(), type=_Witnesses).witnesses
    assert len(rows) == 1050
    return rows


def _bits(point: Vec2) -> tuple[int, int]:
    return struct.unpack("<2I", struct.pack("<2f", point.x, point.y))


def test_aim_point_and_gameplay_dispatch_match_native_witnesses() -> None:
    for i, row in enumerate(_witnesses()):
        position = Vec2(row.position_x, row.position_y)
        expected = (row.aim_x_bits, row.aim_y_bits)
        assert _bits(native_aim_point_from_heading(position, row.heading)) == expected, i
        for scheme in (AimScheme.KEYBOARD, AimScheme.JOYSTICK):
            player = PlayerState(index=0, pos=position, aim_heading=row.heading)
            _player_update_aim_by_scheme(
                player=player,
                input_state=player_input(move=Vec2(), aim=Vec2()),
                dt=0.0,
                movement_mode=MovementControlType.STATIC,
                aim_scheme=scheme,
                creatures=[],
            )
            assert _bits(player.aim) == expected, (i, scheme)


class _TurnWitness(_Witness, frozen=True):
    dt: float
    scheme: int
    left: bool
    right: bool


class _TurnWitnesses(msgspec.Struct, frozen=True):
    witnesses: list[_TurnWitness]


def test_held_aim_controls_match_native_turn_witnesses(monkeypatch: pytest.MonkeyPatch) -> None:
    path = Path(__file__).resolve().parents[2] / "crimson-zig/src/runtime/testdata/player-aim-turns.json"
    rows = msgspec.json.decode(path.read_bytes(), type=_TurnWitnesses).witnesses
    assert len(rows) == 240
    down_codes: set[int] = set()
    monkeypatch.setattr(local_input, "input_code_is_down", lambda code, **_kwargs: int(code) in down_codes)
    monkeypatch.setattr(local_input, "input_code_is_pressed", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(local_input, "input_axis_value", lambda *_args, **_kwargs: 0.0)
    config = default_crimson_cfg(Path("<memory>"))
    config.controls.player(0).movement = MovementControlType.STATIC
    for i, row in enumerate(rows):
        scheme = AimScheme(row.scheme)
        expected = (row.aim_x_bits, row.aim_y_bits)
        player = PlayerState(index=0, pos=Vec2(row.position_x, row.position_y), aim_heading=row.heading)
        _player_update_aim_by_scheme(
            player=player,
            input_state=player_input(move=Vec2(), aim=Vec2(), aim_turn_left=row.left, aim_turn_right=row.right),
            dt=row.dt,
            movement_mode=MovementControlType.STATIC,
            aim_scheme=scheme,
            creatures=[],
        )
        assert _bits(player.aim) == expected, (i, "gameplay")
        config.controls.player(0).aim_scheme = scheme
        left_code, right_code = (
            config.controls.player(0).keyboard_aim_codes
            if scheme == AimScheme.KEYBOARD
            else (local_input._AIM_POV_LEFT_CODE, local_input._AIM_POV_RIGHT_CODE)
        )
        down_codes = ({left_code} if row.left else set()) | ({right_code} if row.right else set())
        player = PlayerState(index=0, pos=Vec2(row.position_x, row.position_y), aim_heading=row.heading)
        interpreter = local_input.LocalInputInterpreter()
        interpreter.reset(players=[player])
        result = interpreter.build_player_input(
            player_index=0,
            player=player,
            config=config,
            mouse_screen=Vec2(),
            mouse_world=Vec2(),
        )
        # The live input records the held controls; the sim turns the heading.
        assert (result.aim_turn_left, result.aim_turn_right) == (row.left, row.right), (i, "local input")
