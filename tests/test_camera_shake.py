from __future__ import annotations

from grim.geom import Vec2

from dataclasses import dataclass
import math
from pathlib import Path

from crimson.bonuses import BonusId
from crimson.bonuses.apply import bonus_apply
from crimson.camera import camera_shake_update
from crimson.game_world import GameWorld
from crimson.gameplay import GameplayState, PlayerInput, PlayerState
from crimson.sim.runners.common import build_damage_scale_by_type, build_empty_fx_queues, reset_players
from crimson.sim.sessions import RushDeterministicSession, SurvivalDeterministicSession
from crimson.sim.world_state import WorldState


@dataclass(slots=True)
class _Creature:
    pos: Vec2
    hp: float
    active: bool = True
    hitbox_size: float = 16.0
    size: float = 50.0
    flags: int = 0
    plague_infected: bool = False


def test_camera_shake_update_resets_offsets_when_inactive() -> None:
    state = GameplayState()
    state.camera_shake_timer = 0.0
    state.camera_shake_offset = Vec2(5.0, -3.0)

    camera_shake_update(state, 0.016)

    assert state.camera_shake_offset == Vec2()


def test_camera_shake_update_decays_timer_without_pulse() -> None:
    state = GameplayState()
    state.camera_shake_timer = 1.0
    state.camera_shake_pulses = 10
    state.camera_shake_offset = Vec2(7.0, -9.0)

    camera_shake_update(state, 0.1)

    assert math.isclose(state.camera_shake_timer, 0.7, abs_tol=1e-9)
    assert state.camera_shake_pulses == 10
    assert state.camera_shake_offset == Vec2(7.0, -9.0)


def test_camera_shake_update_matches_decompile_first_pulse() -> None:
    state = GameplayState()
    state.rng.srand(0xBEEF)
    state.camera_shake_pulses = 0x14
    state.camera_shake_timer = 0.2

    camera_shake_update(state, 0.1)

    assert state.camera_shake_pulses == 0x13
    assert math.isclose(state.camera_shake_timer, 0.1, abs_tol=1e-9)
    assert state.camera_shake_offset == Vec2(28.0, -32.0)


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
    state.camera_shake_offset = Vec2(11.0, -13.0)

    camera_shake_update(state, 0.1)

    assert state.camera_shake_pulses == 0
    assert math.isclose(state.camera_shake_timer, 0.0, abs_tol=1e-9)
    assert state.camera_shake_offset == Vec2(11.0, -13.0)

    camera_shake_update(state, 0.1)

    assert state.camera_shake_offset == Vec2()


def test_bonus_apply_nuke_starts_camera_shake_and_damages_creatures() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    creatures = [_Creature(pos=Vec2(100.0, 100.0), hp=100.0), _Creature(pos=Vec2(500.0, 500.0), hp=100.0)]

    bonus_apply(state, player, BonusId.NUKE, origin=player, creatures=creatures)

    assert state.camera_shake_pulses == 0x14
    assert math.isclose(state.camera_shake_timer, 0.2, abs_tol=1e-9)
    assert creatures[0].hp <= 0.0
    assert creatures[1].hp == 100.0


def test_game_world_nuke_pickup_defers_shake_decay_to_next_frame() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    world = GameWorld(assets_dir=repo_root / "artifacts" / "assets")

    player = world.players[0]
    entry = world.state.bonus_pool.spawn_at(pos=Vec2(player.pos.x, player.pos.y), bonus_id=int(BonusId.NUKE), state=world.state)
    assert entry is not None

    world.update(1.0 / 60.0, perk_progression_enabled=False)

    assert entry.picked
    assert world.state.camera_shake_pulses == 0x14
    assert math.isclose(world.state.camera_shake_timer, 0.2, abs_tol=1e-9)


def _spawn_nuke_pickup_on_player(world: WorldState) -> object:
    player = world.players[0]
    entry = world.state.bonus_pool.spawn_at(
        pos=Vec2(player.pos.x, player.pos.y),
        bonus_id=int(BonusId.NUKE),
        state=world.state,
    )
    assert entry is not None
    return entry


def _build_session_world(*, seed: int = 0x1234, world_size: float = 1024.0) -> WorldState:
    world = WorldState.build(
        world_size=float(world_size),
        demo_mode_active=False,
        hardcore=False,
        difficulty_level=0,
    )
    reset_players(world.players, world_size=float(world_size), player_count=1)
    world.state.rng.srand(int(seed))
    return world


def test_survival_session_nuke_pickup_skips_deferred_camera_decay() -> None:
    world = _build_session_world(seed=0x1234)
    entry = _spawn_nuke_pickup_on_player(world)
    player = world.players[0]
    fx_queue, fx_queue_rotated = build_empty_fx_queues()
    session = SurvivalDeterministicSession(
        world=world,
        world_size=1024.0,
        damage_scale_by_type=build_damage_scale_by_type(),
        fx_queue=fx_queue,
        fx_queue_rotated=fx_queue_rotated,
        perk_progression_enabled=False,
    )

    tick = session.step_tick(
        dt_frame=1.0 / 60.0,
        inputs=[PlayerInput(aim=Vec2(player.pos.x, player.pos.y))],
    )

    assert bool(getattr(entry, "picked", False))
    assert world.state.camera_shake_pulses == 0x14
    assert math.isclose(world.state.camera_shake_timer, 0.2, abs_tol=1e-9)
    assert tick.rng_marks["after_camera_update"] == tick.rng_marks["after_wave_spawns"]


def test_rush_session_nuke_pickup_skips_deferred_camera_decay() -> None:
    world = _build_session_world(seed=0x5678)
    entry = _spawn_nuke_pickup_on_player(world)
    player = world.players[0]
    fx_queue, fx_queue_rotated = build_empty_fx_queues()
    session = RushDeterministicSession(
        world=world,
        world_size=1024.0,
        damage_scale_by_type=build_damage_scale_by_type(),
        fx_queue=fx_queue,
        fx_queue_rotated=fx_queue_rotated,
    )

    tick = session.step_tick(
        dt_frame=1.0 / 60.0,
        inputs=[PlayerInput(aim=Vec2(player.pos.x, player.pos.y))],
    )

    assert bool(getattr(entry, "picked", False))
    assert world.state.camera_shake_pulses == 0x14
    assert math.isclose(world.state.camera_shake_timer, 0.2, abs_tol=1e-9)
    assert tick.rng_marks["after_camera_update"] == tick.rng_marks["after_rush_spawns"]
