from __future__ import annotations

from dataclasses import dataclass
import math

from crimson.camera import camera_shake_update
from crimson.gameplay import BonusId, GameplayState, PlayerState, bonus_apply


@dataclass(slots=True)
class _Creature:
    x: float
    y: float
    hp: float


def test_camera_shake_update_resets_offsets_when_inactive() -> None:
    state = GameplayState()
    state.camera_shake_timer = 0.0
    state.camera_shake_offset_x = 5.0
    state.camera_shake_offset_y = -3.0

    camera_shake_update(state, 0.016)

    assert state.camera_shake_offset_x == 0.0
    assert state.camera_shake_offset_y == 0.0


def test_camera_shake_update_decays_timer_without_pulse() -> None:
    state = GameplayState()
    state.camera_shake_timer = 1.0
    state.camera_shake_pulses = 10
    state.camera_shake_offset_x = 7.0
    state.camera_shake_offset_y = -9.0

    camera_shake_update(state, 0.1)

    assert math.isclose(state.camera_shake_timer, 0.7, abs_tol=1e-9)
    assert state.camera_shake_pulses == 10
    assert state.camera_shake_offset_x == 7.0
    assert state.camera_shake_offset_y == -9.0


def test_camera_shake_update_matches_decompile_first_pulse() -> None:
    state = GameplayState()
    state.rng.srand(0xBEEF)
    state.camera_shake_pulses = 0x14
    state.camera_shake_timer = 0.2

    camera_shake_update(state, 0.1)

    assert state.camera_shake_pulses == 0x13
    assert math.isclose(state.camera_shake_timer, 0.1, abs_tol=1e-9)
    assert state.camera_shake_offset_x == 28.0
    assert state.camera_shake_offset_y == -32.0


def test_camera_shake_update_reflex_boost_uses_shorter_interval() -> None:
    state = GameplayState()
    state.bonuses.reflex_boost = 1.0
    state.camera_shake_pulses = 5
    state.camera_shake_timer = 0.01

    camera_shake_update(state, 0.1)

    assert state.camera_shake_pulses == 4
    assert math.isclose(state.camera_shake_timer, 0.06, abs_tol=1e-9)


def test_camera_shake_update_clears_offsets_one_frame_after_last_pulse() -> None:
    state = GameplayState()
    state.camera_shake_pulses = 1
    state.camera_shake_timer = 0.01
    state.camera_shake_offset_x = 11.0
    state.camera_shake_offset_y = -13.0

    camera_shake_update(state, 0.1)

    assert state.camera_shake_pulses == 0
    assert math.isclose(state.camera_shake_timer, 0.0, abs_tol=1e-9)
    assert state.camera_shake_offset_x == 11.0
    assert state.camera_shake_offset_y == -13.0

    camera_shake_update(state, 0.1)

    assert state.camera_shake_offset_x == 0.0
    assert state.camera_shake_offset_y == 0.0


def test_bonus_apply_nuke_starts_camera_shake_and_damages_creatures() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos_x=100.0, pos_y=100.0)
    creatures = [_Creature(x=100.0, y=100.0, hp=100.0), _Creature(x=500.0, y=500.0, hp=100.0)]

    bonus_apply(state, player, BonusId.NUKE, origin=player, creatures=creatures)

    assert state.camera_shake_pulses == 0x14
    assert math.isclose(state.camera_shake_timer, 0.2, abs_tol=1e-9)
    assert creatures[0].hp <= 0.0
    assert creatures[1].hp == 100.0

