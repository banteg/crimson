from __future__ import annotations

from crimson.creatures.runtime import CreatureState
from crimson.effects import EffectPool
from crimson.gameplay import GameplayState
from crimson.owner_ref import OwnerRef
from crimson.projectiles.effects import _spawn_ion_hit_effects
from crimson.projectiles.runtime import PrimaryStepCtx, ProjectilePool
from crimson.projectiles.types import ProjectileTemplateId
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from grim.sfx_map import SfxId
from tests.support.factories import make_projectile_update_options
from tests.support.helpers import ScriptedCrand, assert_float_close


def test_plasma_cannon_hit_spawns_rings_and_sfx() -> None:
    pool = ProjectilePool(size=64)
    creature = CreatureState(active=True, hp=100.0, pos=Vec2(), size=50.0)
    runtime_state = GameplayState()

    pool.spawn(
        pos=Vec2(),
        angle=0.0,
        type_id=ProjectileTemplateId.PLASMA_CANNON,
        owner=OwnerRef.from_local_player(0),
        travel_budget=10.0,
    )

    pool.step(
        PrimaryStepCtx(
            dt=0.016,
            creatures=[creature],
            options=make_projectile_update_options(
                world_size=4096.0,
                detail_preset=5,
                rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
                runtime_state=runtime_state,
            ),
        ),
    )

    assert runtime_state.sfx_queue == [SfxId.EXPLOSION_MEDIUM, SfxId.SHOCKWAVE]

    rings = [entry for entry in runtime_state.effects.iter_active() if int(entry.effect_id) == 1]
    assert len(rings) == 2
    for actual, expected in zip(sorted(float(entry.scale_step) for entry in rings), (45.0, 67.5)):
        assert_float_close(actual, expected)

    spawned = [p for p in pool.entries if p.active and int(p.type_id) == int(ProjectileTemplateId.PLASMA_RIFLE)]
    assert len(spawned) == 12


def test_splitter_gun_hit_spawns_split_projectiles_and_sparks() -> None:
    pool = ProjectilePool(size=64)
    creature = CreatureState(active=True, hp=100.0, pos=Vec2(), size=50.0)
    runtime_state = GameplayState()
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    pool.spawn(
        pos=Vec2(),
        angle=0.0,
        type_id=ProjectileTemplateId.SPLITTER_GUN,
        owner=OwnerRef.from_local_player(0),
        travel_budget=30.0,
    )

    pool.step(
        PrimaryStepCtx(
            dt=0.016,
            creatures=[creature],
            options=make_projectile_update_options(
                world_size=4096.0,
                detail_preset=5,
                rng=rng,
                runtime_state=runtime_state,
            ),
        ),
    )

    sparks = [entry for entry in runtime_state.effects.iter_active() if int(entry.effect_id) == 0]
    assert len(sparks) == 3
    assert all(int(entry.flags) == 0x19 for entry in sparks)

    split = [
        p
        for p in pool.entries
        if p.active
        and int(p.type_id) == int(ProjectileTemplateId.SPLITTER_GUN)
        and p.owner == OwnerRef.from_creature(0)
    ]
    assert len(split) == 2
    assert all(bool(p.hits_players) for p in split)
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
    pool = ProjectilePool(size=64)
    creature = CreatureState(active=True, hp=100.0, pos=Vec2(), size=50.0)
    player = PlayerState(index=0, pos=Vec2())

    pool.spawn(
        pos=Vec2(),
        angle=0.0,
        type_id=ProjectileTemplateId.SPLITTER_GUN,
        owner=OwnerRef.from_local_player(0),
        travel_budget=30.0,
    )

    pool.step(
        PrimaryStepCtx(
            dt=0.016,
            creatures=[creature],
            options=make_projectile_update_options(
                world_size=4096.0,
                detail_preset=5,
                rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
                players=[player],
            ),
        ),
    )

    assert float(player.health) < 100.0


def test_shrinkifier_hit_spawns_native_hit_effects() -> None:
    pool = ProjectilePool(size=64)
    creature = CreatureState(active=True, hp=100.0, pos=Vec2(), size=50.0)
    runtime_state = GameplayState()
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    pool.spawn(
        pos=Vec2(),
        angle=0.0,
        type_id=ProjectileTemplateId.SHRINKIFIER,
        owner=OwnerRef.from_local_player(0),
        travel_budget=10.0,
    )

    pool.step(
        PrimaryStepCtx(
            dt=0.016,
            creatures=[creature],
            options=make_projectile_update_options(
                world_size=4096.0,
                detail_preset=5,
                rng=rng,
                runtime_state=runtime_state,
            ),
        ),
    )

    effects = runtime_state.effects.iter_active()
    rings = [entry for entry in effects if int(entry.effect_id) == 1]
    bursts = [entry for entry in effects if int(entry.effect_id) == 0]

    assert len(rings) == 1
    assert len(bursts) == 4

    ring = rings[0]
    assert_float_close(float(ring.scale_step), -4.0)
    assert_float_close(float(ring.lifetime), 0.3)
    assert_float_close(float(ring.half_width), 36.0)

    assert_float_close(float(creature.size), 32.5)
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.PROJECTILE_UPDATE_STOP_ON_HIT_JITTER,
        RngCallerStatic.SHRINKIFIER_HIT_ROTATION,
        RngCallerStatic.SHRINKIFIER_HIT_VEL_X,
        RngCallerStatic.SHRINKIFIER_HIT_VEL_Y,
        RngCallerStatic.SHRINKIFIER_HIT_SCALE_STEP,
        RngCallerStatic.SHRINKIFIER_HIT_ROTATION,
        RngCallerStatic.SHRINKIFIER_HIT_VEL_X,
        RngCallerStatic.SHRINKIFIER_HIT_VEL_Y,
        RngCallerStatic.SHRINKIFIER_HIT_SCALE_STEP,
        RngCallerStatic.SHRINKIFIER_HIT_ROTATION,
        RngCallerStatic.SHRINKIFIER_HIT_VEL_X,
        RngCallerStatic.SHRINKIFIER_HIT_VEL_Y,
        RngCallerStatic.SHRINKIFIER_HIT_SCALE_STEP,
        RngCallerStatic.SHRINKIFIER_HIT_ROTATION,
        RngCallerStatic.SHRINKIFIER_HIT_VEL_X,
        RngCallerStatic.SHRINKIFIER_HIT_VEL_Y,
        RngCallerStatic.SHRINKIFIER_HIT_SCALE_STEP,
    ]


def test_ion_hit_effects_tag_exact_native_callers() -> None:
    effects = EffectPool(size=64)
    sfx_queue: list[SfxId] = []
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

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


def test_non_gauss_freeze_hit_pool_step_leaves_shard_to_presentation(mocker) -> None:
    pool = ProjectilePool(size=64)
    creature = CreatureState(active=True, hp=100.0, pos=Vec2(), size=50.0)
    runtime_state = GameplayState()
    runtime_state.bonuses.freeze = 1.0
    spawn_freeze_shard = mocker.patch.object(
        runtime_state.effects,
        "spawn_freeze_shard",
        wraps=runtime_state.effects.spawn_freeze_shard,
    )

    pool.spawn(
        pos=Vec2(),
        angle=0.0,
        type_id=ProjectileTemplateId.PISTOL,
        owner=OwnerRef.from_local_player(0),
        travel_budget=10.0,
    )

    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    pool.step(
        PrimaryStepCtx(
            dt=0.016,
            creatures=[creature],
            options=make_projectile_update_options(
                world_size=4096.0,
                detail_preset=5,
                rng=rng,
                runtime_state=runtime_state,
            ),
        ),
    )

    # Native spawns the default freeze shard in the post-hit decal branch,
    # after the burn draw (see queue_projectile_decals_post_hit).
    assert spawn_freeze_shard.call_count == 0
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.PROJECTILE_UPDATE_STOP_ON_HIT_JITTER,
    ]


def test_non_gauss_freeze_hit_presentation_draws_burn_then_single_shard(mocker) -> None:
    from crimson.effects import FxQueue
    from crimson.projectiles.types import ProjectileHit
    from crimson.sim.presentation_step import (
        queue_projectile_decals_post_hit,
        queue_projectile_decals_pre_hit,
    )

    state = GameplayState()
    state.bonuses.freeze = 1.0
    state.rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    spawn_freeze_shard = mocker.patch.object(
        state.effects,
        "spawn_freeze_shard",
        wraps=state.effects.spawn_freeze_shard,
    )
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    hit = ProjectileHit(
        type_id=ProjectileTemplateId.PISTOL,
        origin=Vec2(90.0, 90.0),
        hit=Vec2(100.0, 100.0),
        target=Vec2(100.0, 100.0),
    )
    fx_queue = FxQueue()

    post_ctx = queue_projectile_decals_pre_hit(
        state=state,
        players=[player],
        fx_queue=fx_queue,
        hit=hit,
        rng=state.rng,
        detail_preset=5,
        violence_disabled=0,
    )
    queue_projectile_decals_post_hit(
        fx_queue=fx_queue,
        post_ctx=post_ctx,
        rng=state.rng,
    )

    assert spawn_freeze_shard.call_count == 1
    assert [record.caller for record in state.rng.records_since()] == [
        RngCallerStatic.PROJECTILE_UPDATE_POST_HIT_DECAL_BURN,
        RngCallerStatic.PROJECTILE_UPDATE_DEFAULT_FREEZE_SHARD_ANGLE,
        RngCallerStatic.EFFECT_SPAWN_FREEZE_SHARD_LIFETIME,
        RngCallerStatic.EFFECT_SPAWN_FREEZE_SHARD_ROTATION,
        RngCallerStatic.EFFECT_SPAWN_FREEZE_SHARD_HALF,
        RngCallerStatic.EFFECT_SPAWN_FREEZE_SHARD_ROTATION_STEP,
        RngCallerStatic.EFFECT_SPAWN_FREEZE_SHARD_SCALE_STEP,
        RngCallerStatic.EFFECT_SPAWN_FREEZE_SHARD_EFFECT_ID,
    ]
