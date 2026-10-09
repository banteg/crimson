from __future__ import annotations

from crimson.creatures.runtime import CreatureState
from crimson.creatures.spawn import CreatureFlags
from crimson.math_parity import f32
from crimson.owner_id import OWNER_LOCAL_PLAYER
from crimson.projectiles.runtime import projectile_spawn
from crimson.projectiles.types import ProjectileTemplateId
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.world_state import WorldState, WorldStepRuntime
from grim.geom import Vec2
from grim.rand import RecordingCrand
from tests.support.builders.session import make_world
from tests.support.factories import make_step_runtime, place_creatures
from tests.support.helpers import assert_float_close

_SHRINKIFIER_HIT_CALLERS = [
    RngCallerStatic.SHRINKIFIER_HIT_ROTATION,
    RngCallerStatic.SHRINKIFIER_HIT_VEL_X,
    RngCallerStatic.SHRINKIFIER_HIT_VEL_Y,
    RngCallerStatic.SHRINKIFIER_HIT_SCALE_STEP,
] * 4


def _world_with_creature(creature: CreatureState) -> tuple[WorldState, RecordingCrand]:
    world = make_world()
    rng = RecordingCrand(world.state.rng)
    world.state.rng = rng
    place_creatures(world, [creature])
    return world, rng


def _fire_at_creature(world: WorldState, type_id: ProjectileTemplateId) -> WorldStepRuntime:
    projectile_spawn(
        world.state,
        players=world.players,
        pos=Vec2(),
        angle=0.0,
        type_id=type_id,
        owner_id=OWNER_LOCAL_PLAYER,
        owner_player_index=0,
    )
    step_runtime = make_step_runtime(world, dt=0.016)
    world.state.projectiles.step(
        step_runtime,
    )
    return step_runtime


def test_shrinkifier_hit_spawns_native_hit_effects() -> None:
    creature = CreatureState(active=True, hp=100.0, pos=Vec2(), size=50.0)
    world, rng = _world_with_creature(creature)

    _fire_at_creature(world, ProjectileTemplateId.SHRINKIFIER)

    effects = world.state.effects.iter_active()
    rings = [entry for entry in effects if int(entry.effect_id) == 1]
    bursts = [entry for entry in effects if int(entry.effect_id) == 0]

    assert len(rings) == 1
    assert len(bursts) == 4

    ring = rings[0]
    assert_float_close(float(ring.scale_step), -4.0)
    assert ring.lifetime == f32(0.3)
    assert_float_close(float(ring.half_width), 36.0)

    assert_float_close(float(creature.size), 32.5)
    # The hit effects run between the stop-on-hit jitter and the damage call.
    callers = [record.caller for record in rng.records_since()]
    start = callers.index(RngCallerStatic.PROJECTILE_UPDATE_STOP_ON_HIT_JITTER)
    assert callers[start : start + 18] == [
        RngCallerStatic.PROJECTILE_UPDATE_STOP_ON_HIT_JITTER,
        *_SHRINKIFIER_HIT_CALLERS,
        RngCallerStatic.CREATURE_APPLY_DAMAGE_HEADING_JITTER,
    ]


def test_shrinkifier_shrink_death_bypasses_damage_pipeline() -> None:
    creature = CreatureState(active=True, hp=100.0, pos=Vec2(), size=20.0, flags=CreatureFlags(0))
    world, rng = _world_with_creature(creature)

    step_runtime = _fire_at_creature(world, ProjectileTemplateId.SHRINKIFIER)

    assert [death.index for death in step_runtime.deaths] == [0]
    # Native shrink-death goes straight to creature_handle_death with no
    # death-SFX or shock-burst draws.
    assert step_runtime.sfx == []
    assert RngCallerStatic.CREATURE_APPLY_DAMAGE_DEATH_SFX not in {record.caller for record in rng.records_since()}
    assert_float_close(creature.size, 13.0)
    # The generic chip damage still applies after the direct shrink-death;
    # native leaves hp positive when entering it.
    assert creature.hp < 100.0
