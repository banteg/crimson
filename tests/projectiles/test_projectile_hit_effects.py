from __future__ import annotations

from crimson.creatures.runtime import CreatureState
from crimson.creatures.spawn import CreatureFlags
from crimson.effects import EffectPool
from crimson.math_parity import f32
from crimson.owner_id import OWNER_LOCAL_PLAYER
from crimson.projectiles.effects import _spawn_ion_hit_effects
from crimson.projectiles.types import ProjectileTemplateId
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.world_state import WorldState, WorldStepRuntime
from grim.geom import Vec2
from grim.rand import Crand, RecordingCrand
from grim.sfx_map import SfxId
from grim.sfx_types import SfxRequest
from tests.support.audio import sfx_ids
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
    world.state.projectiles.spawn(
        pos=Vec2(),
        angle=0.0,
        type_id=type_id,
        owner_id=OWNER_LOCAL_PLAYER,
    )
    step_runtime = make_step_runtime(world, dt=0.016)
    world.state.projectiles.step(
        step_runtime,
    )
    return step_runtime


def test_plasma_cannon_hit_spawns_rings_and_sfx() -> None:
    world, _rng = _world_with_creature(CreatureState(active=True, hp=100.0, pos=Vec2(), size=50.0))
    runtime_state = world.state
    runtime_state.bonus_spawn_guard = True

    _fire_at_creature(world, ProjectileTemplateId.PLASMA_CANNON)

    assert sfx_ids(runtime_state.sfx_queue) == [SfxId.EXPLOSION_MEDIUM, SfxId.SHOCKWAVE]
    assert not runtime_state.bonus_spawn_guard

    rings = [entry for entry in runtime_state.effects.iter_active() if int(entry.effect_id) == 1]
    assert len(rings) == 2
    for actual, expected in zip(sorted(float(entry.scale_step) for entry in rings), (45.0, 67.5), strict=True):
        assert_float_close(actual, expected)

    spawned = [
        p
        for p in runtime_state.projectiles.entries
        if p.active and int(p.type_id) == int(ProjectileTemplateId.PLASMA_RIFLE)
    ]
    assert len(spawned) == 12


def test_splitter_gun_hit_spawns_split_projectiles_and_sparks() -> None:
    world, rng = _world_with_creature(CreatureState(active=True, hp=100.0, pos=Vec2(), size=50.0))

    _fire_at_creature(world, ProjectileTemplateId.SPLITTER_GUN)

    sparks = [entry for entry in world.state.effects.iter_active() if int(entry.effect_id) == 0]
    assert len(sparks) == 3
    assert all(int(entry.flags) == 0x19 for entry in sparks)

    split = [
        p
        for p in world.state.projectiles.entries
        if p.active
        and int(p.type_id) == int(ProjectileTemplateId.SPLITTER_GUN)
        and p.owner_id == 0
    ]
    assert len(split) == 2
    assert [record.caller for record in rng.records_since()[:9]] == [
        RngCallerStatic.SPLITTER_HIT_ANGLE,
        RngCallerStatic.SPLITTER_HIT_RADIUS,
        RngCallerStatic.SPLITTER_HIT_AGE,
        RngCallerStatic.SPLITTER_HIT_ANGLE,
        RngCallerStatic.SPLITTER_HIT_RADIUS,
        RngCallerStatic.SPLITTER_HIT_AGE,
        RngCallerStatic.SPLITTER_HIT_ANGLE,
        RngCallerStatic.SPLITTER_HIT_RADIUS,
        RngCallerStatic.SPLITTER_HIT_AGE,
    ]


def test_splitter_child_from_owner_minus_100_can_hit_players() -> None:
    world, _rng = _world_with_creature(CreatureState(active=True, hp=100.0, pos=Vec2(), size=50.0))
    player = world.players[0]
    player.pos = Vec2()

    _fire_at_creature(world, ProjectileTemplateId.SPLITTER_GUN)

    assert float(player.health) < 100.0


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


def test_ion_hit_effects_tag_exact_native_callers() -> None:
    effects = EffectPool()
    sfx_queue: list[SfxRequest] = []
    rng = RecordingCrand(Crand(0x1234))

    _spawn_ion_hit_effects(
        effects,
        sfx_queue,
        type_id=ProjectileTemplateId.ION_MINIGUN,
        pos=Vec2(),
        rng=rng,
        detail_preset=5,
    )

    assert sfx_queue == []
    assert len(effects.iter_active()) == 4
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.ION_HIT_SPARK_ROTATION,
        RngCallerStatic.ION_HIT_SPARK_VEL_X,
        RngCallerStatic.ION_HIT_SPARK_VEL_Y,
        RngCallerStatic.ION_HIT_SPARK_SCALE_STEP,
        RngCallerStatic.ION_HIT_SPARK_ROTATION,
        RngCallerStatic.ION_HIT_SPARK_VEL_X,
        RngCallerStatic.ION_HIT_SPARK_VEL_Y,
        RngCallerStatic.ION_HIT_SPARK_SCALE_STEP,
        RngCallerStatic.ION_HIT_SPARK_ROTATION,
        RngCallerStatic.ION_HIT_SPARK_VEL_X,
        RngCallerStatic.ION_HIT_SPARK_VEL_Y,
        RngCallerStatic.ION_HIT_SPARK_SCALE_STEP,
    ]


def test_non_gauss_freeze_hit_draws_burn_then_single_default_shard() -> None:
    world, rng = _world_with_creature(CreatureState(active=True, hp=1000.0, pos=Vec2(), size=50.0))
    world.state.bonuses.freeze = 1.0

    _fire_at_creature(world, ProjectileTemplateId.PISTOL)

    # Native spawns the default freeze shard in the post-hit decal branch,
    # after the burn draw (see queue_projectile_decals_post_hit).
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.PROJECTILE_UPDATE_STOP_ON_HIT_JITTER,
        RngCallerStatic.CREATURE_APPLY_DAMAGE_HEADING_JITTER,
        RngCallerStatic.PROJECTILE_UPDATE_POST_HIT_DECAL_BURN,
        RngCallerStatic.PROJECTILE_UPDATE_DEFAULT_FREEZE_SHARD_ANGLE,
        RngCallerStatic.EFFECT_SPAWN_FREEZE_SHARD_LIFETIME,
        RngCallerStatic.EFFECT_SPAWN_FREEZE_SHARD_ROTATION,
        RngCallerStatic.EFFECT_SPAWN_FREEZE_SHARD_HALF,
        RngCallerStatic.EFFECT_SPAWN_FREEZE_SHARD_ROTATION_STEP,
        RngCallerStatic.EFFECT_SPAWN_FREEZE_SHARD_SCALE_STEP,
        RngCallerStatic.EFFECT_SPAWN_FREEZE_SHARD_EFFECT_ID,
        RngCallerStatic.PROJECTILE_UPDATE_HIT_SFX,
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


def test_secondary_homing_acquires_targets_beyond_1000_units() -> None:
    from crimson.projectiles.runtime.collision import creature_find_nearest_alive

    far_creature = CreatureState(active=True, hp=10.0, lifecycle_stage=16.0, pos=Vec2(1200.0, 900.0))
    creatures = [CreatureState() for _ in range(3)]
    creatures[2] = far_creature

    # Native compares plain distances against a 1e6 seed, so targets farther
    # than 1000 units (offscreen spawns) are still acquired.
    assert creature_find_nearest_alive(creatures=creatures, origin=Vec2(0.0, 0.0)) == 2


def test_secondary_homing_compares_stored_x87_pc24_distances() -> None:
    from crimson.projectiles.runtime.collision import creature_find_nearest_alive

    creatures = [
        CreatureState(
            active=True,
            hp=10.0,
            lifecycle_stage=16.0,
            pos=Vec2(-631.7838745117188, -249.09634399414062),
        ),
        CreatureState(
            active=True,
            hp=10.0,
            lifecycle_stage=16.0,
            pos=Vec2(-627.4663696289062, -259.78033447265625),
        ),
    ]

    # A host-double squared-distance compare chooses slot 0; native narrows the
    # x87 fsqrt result and slot 1 is strictly closer at that precision.
    assert creature_find_nearest_alive(creatures=creatures, origin=Vec2()) == 1


def test_shock_chain_retarget_compares_stored_x87_pc24_distances() -> None:
    from crimson.projectiles.runtime.collision import creature_find_nearest_active

    creatures = [
        CreatureState(
            active=True,
            hp=10.0,
            pos=Vec2(-1727.156494140625, -1351.4605712890625),
        ),
        CreatureState(
            active=True,
            hp=10.0,
            pos=Vec2(1722.1292724609375, -1357.8604736328125),
        ),
    ]

    # Host-double squared distances prefer slot 1. Native stores equal PC=24
    # fsqrt results, so its strict comparison retains the earlier slot 0.
    assert Vec2.distance_sq(Vec2(), creatures[0].pos) > Vec2.distance_sq(Vec2(), creatures[1].pos)
    assert (
        creature_find_nearest_active(
            creatures=creatures,
            origin=Vec2(),
            exclude_id=2,
            min_dist=100.0,
        )
        == 0
    )
