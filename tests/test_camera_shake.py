from __future__ import annotations

from dataclasses import dataclass
import math
from pathlib import Path

from crimson.camera import camera_shake_update
from crimson.game_world import GameWorld
from crimson.gameplay import BonusId, GameplayState, PlayerState, bonus_apply


@dataclass(slots=True)
class _Creature:
    x: float
    y: float
    hp: float
    active: bool = True
    hitbox_size: float = 16.0
    size: float = 50.0


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


def test_game_world_nuke_pickup_defers_shake_decay_to_next_frame() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    world = GameWorld(assets_dir=repo_root / "artifacts" / "assets")

    player = world.players[0]
    entry = world.state.bonus_pool.spawn_at(player.pos_x, player.pos_y, int(BonusId.NUKE), state=world.state)
    assert entry is not None

    world.update(1.0 / 60.0, perk_progression_enabled=False)

    assert entry.picked
    assert world.state.camera_shake_pulses == 0x14
    assert math.isclose(world.state.camera_shake_timer, 0.2, abs_tol=1e-9)
