from __future__ import annotations

import math

from crimson.creatures.runtime import CreatureState
from crimson.effects import EffectPool, FxQueue, FxQueueRotated, ParticlePool, ParticleStyleId, SpriteEffectPool
from crimson.effects_atlas import effect_src_rect
from crimson.math_parity import f32
from crimson.owner_ref import OwnerRef
from crimson.rng_caller_static import RngCallerStatic
from grim.color import RGBA
from grim.geom import Vec2
from tests.support.factories import RecordingCreatureDamageRuntime
from tests.support.helpers import ScriptedCrand, assert_float_close


def test_effect_src_rect_uses_grid_and_frame() -> None:
    # effect_id 0x00: size_code 0x80 -> grid 2, frame 0x02 -> (col=0,row=1)
    rect = effect_src_rect(0x00, texture_width=200.0, texture_height=100.0)
    assert rect == (0.0, 50.0, 100.0, 50.0)


def test_fx_queue_caps_count() -> None:
    q = FxQueue(capacity=4, max_count=3)
    rgba = RGBA(1.0, 1.0, 1.0, 1.0)
    assert q.add(effect_id=0, pos=Vec2(), width=10.0, height=10.0, rotation=0.0, rgba=rgba)
    assert q.add(effect_id=0, pos=Vec2(), width=10.0, height=10.0, rotation=0.0, rgba=rgba)
    assert q.add(effect_id=0, pos=Vec2(), width=10.0, height=10.0, rotation=0.0, rgba=rgba)
    assert not q.add(effect_id=0, pos=Vec2(), width=10.0, height=10.0, rotation=0.0, rgba=rgba)
    assert q.count == 3


def test_fx_queue_add_random_tags_exact_native_callers() -> None:
    rng = ScriptedCrand([0, 0, 0, 0])
    q = FxQueue(capacity=4, max_count=4)

    assert q.add_random(pos=Vec2(), rng=rng)
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.FX_QUEUE_ADD_RANDOM_GRAY,
        RngCallerStatic.FX_QUEUE_ADD_RANDOM_WIDTH,
        RngCallerStatic.FX_QUEUE_ADD_RANDOM_ROTATION,
        RngCallerStatic.FX_QUEUE_ADD_RANDOM_EFFECT_ID,
    ]


def test_particle_pool_tags_exact_native_callers() -> None:
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    pool = ParticlePool(size=1, rng=rng)

    pool.spawn_particle(pos=Vec2(), angle=0.0, intensity=1.0)
    pool.spawn_particle(pos=Vec2(), angle=0.0, intensity=1.0)
    pool.spawn_particle_slow(pos=Vec2(), angle=0.0)

    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.FX_SPAWN_PARTICLE_SPIN,
        RngCallerStatic.FX_SPAWN_PARTICLE_ALLOC,
        RngCallerStatic.FX_SPAWN_PARTICLE_SPIN,
        RngCallerStatic.FX_SPAWN_PARTICLE_SLOW_ALLOC,
        RngCallerStatic.FX_SPAWN_PARTICLE_SLOW_SPIN,
    ]


def test_particle_spawn_keeps_native_wide_trig_until_speed_multiply() -> None:
    rng = ScriptedCrand([5, 5])
    pool = ParticlePool(size=2, rng=rng)

    fast_idx = pool.spawn_particle(
        pos=Vec2(1.0 + 1e-8, 2.0 + 1e-8),
        angle=f32(0.0014),
        intensity=1.0 + 1e-8,
    )
    slow_idx = pool.spawn_particle_slow(pos=Vec2(), angle=f32(0.0009))

    fast = pool.entries[fast_idx]
    assert fast.pos == Vec2(1.0, 2.0)
    assert fast.vel == Vec2(89.99990844726562, 0.12599995732307434)
    assert fast.intensity == 1.0
    assert fast.spin == 0.04999999701976776

    slow = pool.entries[slow_idx]
    assert slow.vel == Vec2(29.999988555908203, 0.02699999511241913)
    assert slow.spin == 0.04999999701976776


def test_sprite_effect_pool_tags_exact_native_callers() -> None:
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    pool = SpriteEffectPool(size=1, rng=rng)

    pool.spawn(pos=Vec2(), vel=Vec2(), scale=1.0)
    pool.spawn(pos=Vec2(), vel=Vec2(), scale=1.0)

    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.FX_SPAWN_SPRITE_ROTATION,
        RngCallerStatic.FX_SPAWN_SPRITE_ALLOC,
        RngCallerStatic.FX_SPAWN_SPRITE_ROTATION,
    ]


def test_sprite_effect_spawn_canonicalizes_native_f32_fields() -> None:
    pool = SpriteEffectPool(size=1, rng=ScriptedCrand(1, fallback=ScriptedCrand.Fallback.REPEAT_LAST))

    idx = pool.spawn(
        pos=Vec2(1.0 + 1e-8, 2.0 + 1e-8),
        vel=Vec2(3.0 + 1e-8, 4.0 + 1e-8),
        scale=5.0 + 1e-8,
    )
    entry = pool.entries[idx]

    assert entry.pos == Vec2(1.0, 2.0)
    assert entry.vel == Vec2(3.0, 4.0)
    assert entry.scale == 5.0
    assert entry.rotation == 0.009999999776482582


def test_fx_queue_rotated_applies_alpha_adjustment() -> None:
    q = FxQueueRotated(capacity=2, max_count=2)
    assert q.add(
        top_left=Vec2(),
        rgba=RGBA(1.0, 1.0, 1.0, 1.0),
        rotation=0.0,
        scale=64.0,
        creature_type_id=3,
        terrain_bodies_transparency=2.0,
    )
    entry = q.entries[0]
    assert_float_close(entry.color.a, 0.5)

    q.clear()
    assert q.add(
        top_left=Vec2(),
        rgba=RGBA(1.0, 1.0, 1.0, 1.0),
        rotation=0.0,
        scale=64.0,
        creature_type_id=3,
        terrain_bodies_transparency=0.0,
    )
    entry = q.entries[0]
    assert_float_close(entry.color.a, 0.8)


def test_spawn_freeze_shard_tags_exact_native_callers() -> None:
    pool = EffectPool(size=8)
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    pool.spawn_freeze_shard(
        pos=Vec2(),
        angle=0.0,
        rng=rng,
        detail_preset=5,
    )

    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.EFFECT_SPAWN_FREEZE_SHARD_LIFETIME,
        RngCallerStatic.EFFECT_SPAWN_FREEZE_SHARD_ROTATION,
        RngCallerStatic.EFFECT_SPAWN_FREEZE_SHARD_HALF,
        RngCallerStatic.EFFECT_SPAWN_FREEZE_SHARD_ROTATION_STEP,
        RngCallerStatic.EFFECT_SPAWN_FREEZE_SHARD_SCALE_STEP,
        RngCallerStatic.EFFECT_SPAWN_FREEZE_SHARD_EFFECT_ID,
    ]


def test_spawn_freeze_shatter_tags_exact_native_callers() -> None:
    pool = EffectPool(size=32)
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    pool.spawn_freeze_shatter(
        pos=Vec2(),
        angle=0.0,
        rng=rng,
        detail_preset=5,
    )

    expected = [
        RngCallerStatic.EFFECT_SPAWN_FREEZE_SHATTER_HALF,
        RngCallerStatic.EFFECT_SPAWN_FREEZE_SHATTER_ROTATION_STEP,
    ] * 4
    expected.extend(
        [
            RngCallerStatic.EFFECT_SPAWN_FREEZE_SHATTER_SHARD_ANGLE,
            RngCallerStatic.EFFECT_SPAWN_FREEZE_SHARD_LIFETIME,
            RngCallerStatic.EFFECT_SPAWN_FREEZE_SHARD_ROTATION,
            RngCallerStatic.EFFECT_SPAWN_FREEZE_SHARD_HALF,
            RngCallerStatic.EFFECT_SPAWN_FREEZE_SHARD_ROTATION_STEP,
            RngCallerStatic.EFFECT_SPAWN_FREEZE_SHARD_SCALE_STEP,
            RngCallerStatic.EFFECT_SPAWN_FREEZE_SHARD_EFFECT_ID,
        ]
        * 4,
    )
    assert [record.caller for record in rng.records_since()] == expected


def test_sprite_effect_pool_updates_and_expires() -> None:
    pool = SpriteEffectPool(size=1, rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    idx = pool.spawn(pos=Vec2(10.0, 20.0), vel=Vec2(2.0, -3.0), scale=1.0)
    fx = pool.entries[idx]
    assert fx.active
    assert fx.color.a == 1.0
    assert fx.rotation == 0.0

    pool.update(0.5)
    assert_float_close(fx.pos.x, 11.0)
    assert_float_close(fx.pos.y, 18.5)
    assert_float_close(fx.rotation, 1.5)
    assert_float_close(fx.color.a, 0.5)
    assert_float_close(fx.scale, 31.0)

    pool.update(0.6)
    assert not fx.active


def test_particle_pool_style_decay_rules_match_thresholds() -> None:
    pool = ParticlePool(size=2, rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))

    # Style 0 persists until intensity <= 0.0.
    idx0 = pool.spawn_particle(pos=Vec2(), angle=0.0, intensity=1.0)
    p0 = pool.entries[idx0]
    p0.render_flag = False
    pool.update(1.0)
    assert p0.active
    assert_float_close(p0.intensity, f32(0.1))

    # Style 1 expires once intensity <= 0.8.
    idx1 = pool.spawn_particle(pos=Vec2(), angle=0.0, intensity=1.0)
    p1 = pool.entries[idx1]
    p1.render_flag = False
    p1.style_id = ParticleStyleId.BLOW_TORCH
    pool.update(1.0)
    assert not p1.active

    # Style 8 decays slowly and also uses the 0.8 cutoff.
    idx2 = pool.spawn_particle_slow(pos=Vec2(), angle=0.0)
    p2 = pool.entries[idx2]
    p2.render_flag = False
    pool.update(1.0)
    assert p2.active
    assert_float_close(p2.intensity, f32(0.89))


def test_particle_hit_deflects_rescales_spawns_fx_and_pushes_creature() -> None:
    # Rng consumption order:
    # - spawn_particle: spin
    # - update: random-walk jitter
    # - hit: speed_scale
    # - hit: sprite_vel_x, sprite_vel_y
    # - fx_queue.add_random: gray, w, rotation, effect_id
    rng = ScriptedCrand([0, 50, 7, 0, 0, 0, 0, 0, 0], fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    pool = ParticlePool(size=1, rng=rng)
    fx_queue = FxQueue(capacity=1, max_count=1)
    sprite_effects = SpriteEffectPool(size=1, rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))

    particle_id = pool.spawn_particle(
        pos=Vec2(),
        angle=0.0,
        intensity=1.0,
        owner=OwnerRef.from_player(0),
    )
    particle = pool.entries[particle_id]

    creature = CreatureState()
    creature.active = True
    creature.hp = 100.0
    creature.pos = Vec2()
    creature.size = 50.0
    creature.lifecycle_stage = 16.0

    dt = 0.016
    pool.update(dt, creatures=[creature], fx_queue=fx_queue, sprite_effects=sprite_effects)

    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.FX_SPAWN_PARTICLE_SPIN,
        RngCallerStatic.PROJECTILE_UPDATE_PARTICLE_JITTER_FLAMETHROWER,
        RngCallerStatic.PROJECTILE_UPDATE_PARTICLE_BOUNCE_SPEED_SCALE,
        RngCallerStatic.PROJECTILE_UPDATE_PARTICLE_SPRITE_VEL_X,
        RngCallerStatic.PROJECTILE_UPDATE_PARTICLE_SPRITE_VEL_Y,
        RngCallerStatic.FX_QUEUE_ADD_RANDOM_GRAY,
        RngCallerStatic.FX_QUEUE_ADD_RANDOM_WIDTH,
        RngCallerStatic.FX_QUEUE_ADD_RANDOM_ROTATION,
        RngCallerStatic.FX_QUEUE_ADD_RANDOM_EFFECT_ID,
    ]

    assert particle.render_flag is False
    assert fx_queue.count == 1
    assert sprite_effects.entries[0].active
    assert_float_close(sprite_effects.entries[0].color.a, 0.7)

    deflect_step = f32(math.tau * 0.2)
    assert_float_close(float(particle.angle), deflect_step)

    speed_scale = f32(0.7)
    bounce_velocity = Vec2.from_angle(float(particle.angle)) * 82.0
    expected_vel_x = f32(float(bounce_velocity.x) * float(speed_scale))
    expected_vel_y = f32(float(bounce_velocity.y) * float(speed_scale))
    assert_float_close(float(particle.vel.x), expected_vel_x)
    assert_float_close(float(particle.vel.y), expected_vel_y)

    dt_f32 = f32(dt)
    assert_float_close(float(creature.pos.x), f32(float(expected_vel_x) * float(dt_f32)))
    assert_float_close(float(creature.pos.y), f32(float(expected_vel_y) * float(dt_f32)))


def test_particle_pool_tags_style_specific_jitter_callers() -> None:
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    pool = ParticlePool(size=3, rng=rng)

    flame_idx = pool.spawn_particle(pos=Vec2(), angle=0.0, intensity=1.0)
    alt_idx = pool.spawn_particle(pos=Vec2(), angle=0.0, intensity=1.0)
    bubble_idx = pool.spawn_particle_slow(pos=Vec2(), angle=0.0)

    flame = pool.entries[flame_idx]
    alt = pool.entries[alt_idx]
    bubble = pool.entries[bubble_idx]
    alt.style_id = ParticleStyleId.BLOW_TORCH

    before = rng.calls
    pool.update(0.016)

    assert flame.render_flag
    assert alt.render_flag
    assert bubble.render_flag
    assert [record.caller for record in rng.records_since(before)] == [
        RngCallerStatic.PROJECTILE_UPDATE_PARTICLE_JITTER_FLAMETHROWER,
        RngCallerStatic.PROJECTILE_UPDATE_PARTICLE_JITTER_ALT,
        RngCallerStatic.PROJECTILE_UPDATE_PARTICLE_JITTER_BUBBLEGUN,
    ]


def test_particle_update_uses_explicit_damage_applier() -> None:
    def _spawn_hit_particle(pool: ParticlePool) -> None:
        pool.spawn_particle(
            pos=Vec2(),
            angle=0.0,
            intensity=1.0,
            owner=OwnerRef.from_player(0),
        )

    def _new_creature() -> CreatureState:
        creature = CreatureState()
        creature.active = True
        creature.hp = 100.0
        creature.pos = Vec2()
        creature.size = 50.0
        creature.lifecycle_stage = 16.0
        return creature

    pool = ParticlePool(size=1, rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST))
    creature = _new_creature()
    damage_runtime = RecordingCreatureDamageRuntime(creatures=[creature], apply_damage=False)

    _spawn_hit_particle(pool)
    pool.update(0.016, creatures=[creature], creature_damage_runtime=damage_runtime)
    assert len(damage_runtime.calls) == 1
    assert damage_runtime.calls[0][0] == 0
    assert damage_runtime.calls[0][2] == 4
    assert damage_runtime.calls[0][4] == OwnerRef.from_player(0)
    assert_float_close(creature.hp, 100.0)


def test_effect_pool_blood_splatter_queues_decal_on_expiry() -> None:
    q = FxQueue(capacity=8, max_count=8)
    pool = EffectPool(size=8)

    pool.spawn_blood_splatter(
        pos=Vec2(10.0, 20.0),
        angle=0.0,
        age=0.0,
        rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
        detail_preset=5,
        violence_disabled=0,
    )

    assert len(pool.iter_active()) == 2
    assert q.count == 0

    pool.update(0.1, fx_queue=q)
    assert q.count == 0

    pool.update(0.2, fx_queue=q)
    assert q.count == 2

    first = q.iter_active()[0]
    assert first.effect_id == 7
    assert_float_close(first.pos.x, 0.0)
    assert_float_close(first.pos.y, 20.0)
    assert_float_close(first.width, 2.0)
    assert_float_close(first.height, 2.0)
    assert_float_close(first.color.r, 1.0)
    assert_float_close(first.color.g, 1.0)
    assert_float_close(first.color.b, 1.0)
    assert_float_close(first.color.a, 0.8)


def test_spawn_blood_splatter_tags_exact_native_callers() -> None:
    pool = EffectPool(size=8)
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    pool.spawn_blood_splatter(
        pos=Vec2(),
        angle=0.0,
        age=0.0,
        rng=rng,
        detail_preset=5,
        violence_disabled=0,
    )

    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.EFFECT_SPAWN_BLOOD_SPLATTER_ROTATION,
        RngCallerStatic.EFFECT_SPAWN_BLOOD_SPLATTER_HALF,
        RngCallerStatic.EFFECT_SPAWN_BLOOD_SPLATTER_SPEED_X,
        RngCallerStatic.EFFECT_SPAWN_BLOOD_SPLATTER_SPEED_Y,
        RngCallerStatic.EFFECT_SPAWN_BLOOD_SPLATTER_SCALE_STEP,
    ] * 2


def test_effect_pool_shell_casing_queues_decal_on_expiry() -> None:
    q = FxQueue(capacity=4, max_count=4)
    pool = EffectPool(size=4)

    pool.spawn_shell_casing(
        pos=Vec2(10.0, 20.0),
        aim_heading=0.0,
        draws=(0, 0, 0, 0),
        detail_preset=5,
    )

    active = pool.iter_active()
    assert len(active) == 1
    assert active[0].effect_id == 0x12
    assert active[0].flags == 0x1C5
    assert_float_close(active[0].lifetime, 0.15)

    pool.update(0.2, fx_queue=q)
    assert q.count == 1

    entry = q.iter_active()[0]
    assert entry.effect_id == 0x12
    assert_float_close(entry.width, 4.0)
    assert_float_close(entry.height, 4.0)
    assert_float_close(entry.color.a, 0.35)


def test_effect_pool_spawn_burst_matches_template_defaults() -> None:
    pool = EffectPool(size=8)

    pool.spawn_burst(
        pos=Vec2(10.0, 20.0),
        count=3,
        rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
        detail_preset=5,
    )

    active = pool.iter_active()
    assert len(active) == 3
    for entry in active:
        assert entry.effect_id == 0
        assert_float_close(entry.half_width, 32.0)
        assert_float_close(entry.half_height, 32.0)
        assert entry.flags == 0x1D
        assert_float_close(entry.lifetime, 0.5)
        assert_float_close(entry.scale_step, 0.1)


def test_spawn_burst_tags_exact_native_callers() -> None:
    pool = EffectPool(size=8)
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    pool.spawn_burst(
        pos=Vec2(),
        count=2,
        rng=rng,
        detail_preset=5,
    )

    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.EFFECT_SPAWN_BURST_ROTATION,
        RngCallerStatic.EFFECT_SPAWN_BURST_VEL_X,
        RngCallerStatic.EFFECT_SPAWN_BURST_VEL_Y,
        RngCallerStatic.EFFECT_SPAWN_BURST_SCALE_STEP,
    ] * 2


def test_spawn_explosion_burst_tags_exact_native_callers() -> None:
    pool = EffectPool(size=32)
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)

    pool.spawn_explosion_burst(
        pos=Vec2(),
        scale=1.0,
        rng=rng,
        detail_preset=5,
    )

    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.EFFECT_SPAWN_EXPLOSION_BURST_PUFF_ROTATION,
        RngCallerStatic.EFFECT_SPAWN_EXPLOSION_BURST_PUFF_ROTATION,
    ] + [
        RngCallerStatic.EFFECT_SPAWN_EXPLOSION_BURST_ROTATION,
        RngCallerStatic.EFFECT_SPAWN_EXPLOSION_BURST_VEL_X,
        RngCallerStatic.EFFECT_SPAWN_EXPLOSION_BURST_VEL_Y,
        RngCallerStatic.EFFECT_SPAWN_EXPLOSION_BURST_SCALE_STEP,
        RngCallerStatic.EFFECT_SPAWN_EXPLOSION_BURST_ROTATION_STEP,
    ] * 4


def test_effect_pool_spawn_ring_spawns_effect_1() -> None:
    pool = EffectPool(size=4)

    pool.spawn_ring(
        pos=Vec2(3.0, 4.0),
        detail_preset=5,
        color=RGBA(0.6, 0.6, 1.0, 1.0),
    )

    active = pool.iter_active()
    assert len(active) == 1
    entry = active[0]
    assert entry.effect_id == 1
    assert entry.flags == 0x19
    assert_float_close(entry.pos.x, 3.0)
    assert_float_close(entry.pos.y, 4.0)
    assert_float_close(entry.lifetime, 0.25)
    assert_float_close(entry.scale_step, 50.0)
