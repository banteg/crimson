from __future__ import annotations

import math

from crimson.creatures.runtime import CreatureState
from crimson.projectiles.runtime import projectile_spawn
from crimson.projectiles.types import ProjectileTemplateId, SecondaryProjectileTypeId
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.world_state import WorldState
from grim.geom import Vec2
from grim.rand import RecordingCrand
from tests.support.builders.session import make_world
from tests.support.factories import make_creature_state as _creature
from tests.support.factories import make_step_runtime, place_creatures


def _world_with(creatures: list[CreatureState], *, seed: int = 0xBEEF) -> WorldState:
    world = make_world(seed=seed)
    place_creatures(world, creatures)
    return world


def _recording_rng(world: WorldState) -> RecordingCrand:
    rng = RecordingCrand(world.state.rng)
    world.state.rng = rng
    return rng


def _seed_detonation(world: WorldState, *, scale: float) -> None:
    """Slot 0 as a rocket hit leaves it: a detonation at the origin, `vel` holding (t, scale)."""
    entry = world.state.secondary_projectiles.entries[0]
    entry.active = True
    entry.type_id = SecondaryProjectileTypeId.DETONATION
    entry.vel = Vec2(0.0, scale)
    entry.detonation_t = 0.0
    entry.detonation_scale = scale


def test_secondary_detonation_damages_positive_health_corpses() -> None:
    # Native gates the blast on `active && health > 0` only: a Shrinkifier kill
    # keeps positive health, so its fading corpse still takes blast damage.
    creatures = [
        _creature(pos=Vec2(10.0, 0.0), hp=100.0, death_timer=3.0),
        _creature(pos=Vec2(0.0, 10.0), hp=0.0, death_timer=3.0),
    ]
    world = _world_with(creatures)
    _seed_detonation(world, scale=1.0)

    world.state.secondary_projectiles.step(make_step_runtime(world, dt=0.1))

    assert creatures[0].hp < 100.0
    assert creatures[1].hp == 0.0
    assert creatures[1].death_timer == 3.0


def test_stop_on_hit_jitter_draws_after_a_player_hit_in_the_same_update() -> None:
    # A creature-owned shot that hits the player (life_timer 0.25, no break) and then a creature in the same update
    # still draws the stop-on-hit jitter: native `projectile_update` doesn't check life_timer before the draw.
    world = _world_with([_creature(pos=Vec2(60.0, 0.0)), _creature(pos=Vec2(900.0, 900.0))])
    world.players[0].pos = Vec2(12.0, 0.0)
    rng = _recording_rng(world)
    projectile_spawn(
        world.state,
        players=world.players,
        pos=Vec2(),
        angle=math.pi / 2.0,
        type_id=ProjectileTemplateId.PISTOL,
        owner_id=1,
        owner_player_index=0,
    )
    health_before = float(world.players[0].health)

    hits = world.state.projectiles.step(make_step_runtime(world, dt=0.1))

    assert float(world.players[0].health) < health_before
    assert len(hits) == 1
    callers = [RngCallerStatic(record.caller) for record in rng.records_since()]
    assert RngCallerStatic.PROJECTILE_UPDATE_STOP_ON_HIT_JITTER in callers
