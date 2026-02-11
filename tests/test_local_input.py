from __future__ import annotations

import pytest

from crimson import local_input
from crimson.gameplay import PlayerState
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
        staticmethod(lambda _config, *, player_index: (5, 2)),
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
        staticmethod(lambda _config, *, player_index: (5, 2)),
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
        staticmethod(lambda _config, *, player_index: (0, 2)),
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
