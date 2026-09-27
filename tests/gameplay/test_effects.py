from __future__ import annotations

import math

from crimson.effects import (
    FX_QUEUE_MAX_COUNT,
    EffectPool,
    FxQueue,
    FxQueueRotated,
    ParticlePool,
    ParticleStyleId,
    SpriteEffectPool,
)
from crimson.effects_atlas import effect_src_rect
from crimson.math_parity import f32, x87_pc24_add, x87_pc24_mul, x87_pc24_sub
from crimson.owner_ref import OwnerRef
from crimson.perks import PerkId
from crimson.rng_caller_static import RngCallerStatic
from grim.color import RGBA
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.factories import make_creature_state, make_step_runtime, place_creatures
from tests.support.helpers import ScriptedCrand, assert_float_close


def test_effect_src_rect_uses_grid_and_frame() -> None:
    # effect_id 0x00: size_code 0x80 -> grid 2, frame 0x02 -> (col=0,row=1)
    rect = effect_src_rect(0x00, texture_width=200.0, texture_height=100.0)
    assert rect == (0.0, 50.0, 100.0, 50.0)


def test_fx_queue_caps_count() -> None:
    q = FxQueue()
    rgba = RGBA(1.0, 1.0, 1.0, 1.0)
    for _ in range(FX_QUEUE_MAX_COUNT):
        assert q.add(effect_id=0, pos=Vec2(), width=10.0, height=10.0, rotation=0.0, rgba=rgba)
    assert not q.add(effect_id=0, pos=Vec2(), width=10.0, height=10.0, rotation=0.0, rgba=rgba)
    assert q.count == FX_QUEUE_MAX_COUNT


def test_fx_queue_add_random_tags_exact_native_callers() -> None:
    rng = ScriptedCrand([0, 0, 0, 0])
    q = FxQueue()

    assert q.add_random(pos=Vec2(), rng=rng)
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.FX_QUEUE_ADD_RANDOM_GRAY,
        RngCallerStatic.FX_QUEUE_ADD_RANDOM_WIDTH,
        RngCallerStatic.FX_QUEUE_ADD_RANDOM_ROTATION,
        RngCallerStatic.FX_QUEUE_ADD_RANDOM_EFFECT_ID,
    ]


def test_particle_pool_tags_exact_native_callers() -> None:
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    pool = ParticlePool()

    pool.spawn_particle(pos=Vec2(), angle=0.0, intensity=1.0, rng=rng)
    for entry in pool.entries:
        entry.active = True
    pool.spawn_particle(pos=Vec2(), angle=0.0, intensity=1.0, rng=rng)
    pool.spawn_particle_slow(pos=Vec2(), angle=0.0, rng=rng)

    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.FX_SPAWN_PARTICLE_SPIN,
        RngCallerStatic.FX_SPAWN_PARTICLE_ALLOC,
        RngCallerStatic.FX_SPAWN_PARTICLE_SPIN,
        RngCallerStatic.FX_SPAWN_PARTICLE_SLOW_ALLOC,
        RngCallerStatic.FX_SPAWN_PARTICLE_SLOW_SPIN,
    ]


def test_particle_spawn_keeps_native_wide_trig_until_speed_multiply() -> None:
    rng = ScriptedCrand([5, 5])
    pool = ParticlePool()

    fast_idx = pool.spawn_particle(
        pos=Vec2(1.0 + 1e-8, 2.0 + 1e-8),
        angle=f32(0.0014),
        intensity=1.0 + 1e-8,
        rng=rng,
    )
    slow_idx = pool.spawn_particle_slow(pos=Vec2(), angle=f32(0.0009), rng=rng)

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
    pool = SpriteEffectPool()

    pool.spawn(pos=Vec2(), vel=Vec2(), scale=1.0, rng=rng)
    for entry in pool.entries:
        entry.active = True
    pool.spawn(pos=Vec2(), vel=Vec2(), scale=1.0, rng=rng)

    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.FX_SPAWN_SPRITE_ROTATION,
        RngCallerStatic.FX_SPAWN_SPRITE_ALLOC,
        RngCallerStatic.FX_SPAWN_SPRITE_ROTATION,
    ]


def test_sprite_effect_spawn_canonicalizes_native_f32_fields() -> None:
    pool = SpriteEffectPool()

    idx = pool.spawn(
        pos=Vec2(1.0 + 1e-8, 2.0 + 1e-8),
        vel=Vec2(3.0 + 1e-8, 4.0 + 1e-8),
        scale=5.0 + 1e-8,
        rng=ScriptedCrand(1, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
    )
    entry = pool.entries[idx]

    assert entry.pos == Vec2(1.0, 2.0)
    assert entry.vel == Vec2(3.0, 4.0)
    assert entry.scale == 5.0
    assert entry.rotation == 0.009999999776482582


def test_effect_pool_spawn_canonicalizes_native_f32_fields() -> None:
    pool = EffectPool()

    idx = pool.spawn(
        effect_id=3,
        pos=Vec2(1.0 + 1e-8, 2.0 + 1e-8),
        vel=Vec2(3.0 + 1e-8, 4.0 + 1e-8),
        rotation=5.0 + 1e-8,
        scale=6.0 + 1e-8,
        half_width=7.0 + 1e-8,
        half_height=8.0 + 1e-8,
        age=0.1,
        lifetime=0.2,
        flags=0x1D,
        color=RGBA(0.1, 0.2, 0.3, 0.4),
        rotation_step=9.0 + 1e-8,
        scale_step=10.0 + 1e-8,
        detail_preset=5,
    )

    assert idx == 0
    entry = pool.entries[idx]
    assert entry.pos == Vec2(1.0, 2.0)
    assert entry.vel == Vec2(3.0, 4.0)
    assert entry.rotation == 5.0
    assert entry.scale == 6.0
    assert entry.half_width == 7.0
    assert entry.half_height == 8.0
    assert entry.age == 0.10000000149011612
    assert entry.lifetime == 0.20000000298023224
    assert entry.color == RGBA(
        0.10000000149011612,
        0.20000000298023224,
        0.30000001192092896,
        0.4000000059604645,
    )
    assert entry.rotation_step == 9.0
    assert entry.scale_step == 10.0


def test_fx_queue_rotated_applies_alpha_adjustment() -> None:
    q = FxQueueRotated()
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
    assert entry.color.a == f32(0.8)


def test_fx_queue_rotated_texture_failure_is_a_successful_noop() -> None:
    q = FxQueueRotated()
    assert q.add(
        top_left=Vec2(1.0, 2.0),
        rgba=RGBA(1.0, 1.0, 1.0, 1.0),
        rotation=3.0,
        scale=4.0,
        creature_type_id=5,
        terrain_texture_failed=True,
    )
    assert q.count == 0


def test_spawn_freeze_shard_tags_exact_native_callers() -> None:
    pool = EffectPool()
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
    pool = EffectPool()
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
    pool = SpriteEffectPool()
    idx = pool.spawn(
        pos=Vec2(10.0, 20.0),
        vel=Vec2(2.0, -3.0),
        scale=1.0,
        rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
    )
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
    world = make_world()
    rng = world.state.rng
    pool = ParticlePool()
    step_runtime = make_step_runtime(world, dt=1.0)

    # Style 0 persists until intensity <= 0.0.
    idx0 = pool.spawn_particle(pos=Vec2(), angle=0.0, intensity=1.0, rng=rng)
    p0 = pool.entries[idx0]
    p0.render_flag = False
    pool.update(1.0, step_runtime=step_runtime)
    assert p0.active
    assert p0.intensity == 0.10000002384185791  # Native subtracts the f32 0.9 literal.

    # Style 1 expires once intensity <= 0.8.
    idx1 = pool.spawn_particle(pos=Vec2(), angle=0.0, intensity=1.0, rng=rng)
    p1 = pool.entries[idx1]
    p1.render_flag = False
    p1.style_id = ParticleStyleId.BLOW_TORCH
    pool.update(1.0, step_runtime=step_runtime)
    assert not p1.active

    # Style 8 decays slowly and also uses the 0.8 cutoff.
    idx2 = pool.spawn_particle_slow(pos=Vec2(), angle=0.0, rng=rng)
    p2 = pool.entries[idx2]
    p2.render_flag = False
    pool.update(1.0, step_runtime=step_runtime)
    assert p2.active
    assert_float_close(p2.intensity, f32(0.89))


def test_particle_hit_deflects_rescales_spawns_fx_and_pushes_creature() -> None:
    # Rng consumption order:
    # - spawn_particle: spin
    # - update: random-walk jitter
    # - hit: speed_scale
    # - hit: sprite_vel_x, sprite_vel_y, fx_spawn_sprite rotation
    # - fx_queue.add_random: gray, w, rotation, effect_id
    rng = ScriptedCrand([0, 50, 7, 0, 0, 0, 0, 0, 0, 0], fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    world = make_world()
    world.state.rng = rng
    sprite_effects = world.state.sprite_effects
    pool = ParticlePool()
    fx_queue = FxQueue()

    particle_id = pool.spawn_particle(
        pos=Vec2(),
        angle=0.0,
        intensity=1.0,
        owner=OwnerRef.from_player(0),
        rng=rng,
    )
    particle = pool.entries[particle_id]

    creature = make_creature_state(pos=Vec2())
    creature.tint = RGBA(0.9, 0.6, 0.2, 0.8)
    place_creatures(world, [creature])

    dt = 0.016
    pool.update(dt, step_runtime=make_step_runtime(world, dt=dt, fx_queue=fx_queue))

    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.FX_SPAWN_PARTICLE_SPIN,
        RngCallerStatic.PROJECTILE_UPDATE_PARTICLE_JITTER_FLAMETHROWER,
        RngCallerStatic.PROJECTILE_UPDATE_PARTICLE_BOUNCE_SPEED_SCALE,
        RngCallerStatic.PROJECTILE_UPDATE_PARTICLE_SPRITE_VEL_X,
        RngCallerStatic.PROJECTILE_UPDATE_PARTICLE_SPRITE_VEL_Y,
        RngCallerStatic.FX_SPAWN_SPRITE_ROTATION,
        RngCallerStatic.FX_QUEUE_ADD_RANDOM_GRAY,
        RngCallerStatic.FX_QUEUE_ADD_RANDOM_WIDTH,
        RngCallerStatic.FX_QUEUE_ADD_RANDOM_ROTATION,
        RngCallerStatic.FX_QUEUE_ADD_RANDOM_EFFECT_ID,
    ]

    assert particle.render_flag is False
    assert fx_queue.count == 1
    assert sprite_effects.entries[0].active
    assert_float_close(sprite_effects.entries[0].color.a, f32(0.7))

    deflect_step = f32(math.tau * 0.2)
    assert_float_close(float(particle.angle), deflect_step)

    # Native PC24 keeps the trigonometric results wide until multiplication
    # by 82, then multiplies the stored velocity by the once-scaled RNG draw.
    expected_vel_x = 17.737573623657227
    expected_vel_y = 54.590641021728516
    assert_float_close(float(particle.vel.x), expected_vel_x)
    assert_float_close(float(particle.vel.y), expected_vel_y)

    dt_f32 = f32(dt)
    assert_float_close(float(creature.pos.x), x87_pc24_add(0.0, x87_pc24_mul(expected_vel_x, dt_f32)))
    assert_float_close(float(creature.pos.y), x87_pc24_add(0.0, x87_pc24_mul(expected_vel_y, dt_f32)))

    tint_factor = x87_pc24_sub(1.0, x87_pc24_mul(particle.intensity, f32(0.01)))
    assert_float_close(creature.tint.r, x87_pc24_mul(tint_factor, 0.9))
    assert_float_close(creature.tint.g, x87_pc24_mul(tint_factor, 0.6))
    assert_float_close(creature.tint.b, x87_pc24_mul(tint_factor, 0.2))
    assert_float_close(creature.tint.a, f32(0.8))


def test_particle_pool_tags_style_specific_jitter_callers() -> None:
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    world = make_world()
    world.state.rng = rng
    pool = ParticlePool()

    flame_idx = pool.spawn_particle(pos=Vec2(), angle=0.0, intensity=1.0, rng=rng)
    alt_idx = pool.spawn_particle(pos=Vec2(), angle=0.0, intensity=1.0, rng=rng)
    bubble_idx = pool.spawn_particle_slow(pos=Vec2(), angle=0.0, rng=rng)

    flame = pool.entries[flame_idx]
    alt = pool.entries[alt_idx]
    bubble = pool.entries[bubble_idx]
    alt.style_id = ParticleStyleId.BLOW_TORCH

    before = rng.calls
    pool.update(0.016, step_runtime=make_step_runtime(world, dt=0.016))

    assert flame.render_flag
    assert alt.render_flag
    assert bubble.render_flag
    assert [record.caller for record in rng.records_since(before)] == [
        RngCallerStatic.PROJECTILE_UPDATE_PARTICLE_JITTER_FLAMETHROWER,
        RngCallerStatic.PROJECTILE_UPDATE_PARTICLE_JITTER_ALT,
        RngCallerStatic.PROJECTILE_UPDATE_PARTICLE_JITTER_BUBBLEGUN,
    ]


def test_particle_hit_applies_owner_fire_damage() -> None:
    world = make_world()
    world.state.perks[int(PerkId.PYROMANIAC)] = 1
    creatures = place_creatures(world, [make_creature_state(pos=Vec2())])
    pool = ParticlePool()
    pool.spawn_particle(pos=Vec2(), angle=0.0, intensity=1.0, owner=OwnerRef.from_player(0), rng=world.state.rng)

    pool.update(0.016, step_runtime=make_step_runtime(world, dt=0.016))

    # intensity (1 - 0.016 * 0.9) * 10 fire damage, scaled x1.5 by Pyromaniac.
    assert_float_close(creatures[0].hp, f32(85.216))
    assert creatures[0].last_hit_owner == OwnerRef.from_player(0)


def test_effect_pool_blood_splatter_queues_decal_on_expiry() -> None:
    q = FxQueue()
    pool = EffectPool()

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
    assert first.color.a == f32(0.8)


def test_effect_pool_update_keeps_native_f32_lifetime_boundary() -> None:
    pool = EffectPool()
    idx = pool.spawn(
        effect_id=1,
        pos=Vec2(),
        vel=Vec2(),
        rotation=0.0,
        scale=1.0,
        half_width=1.0,
        half_height=1.0,
        age=0.1,
        lifetime=1.0,
        flags=0x19,
        color=RGBA(),
        rotation_step=0.0,
        scale_step=0.0,
        detail_preset=5,
    )

    assert idx == 0
    entry = pool.entries[idx]
    dt = f32(1.0 / 60.0)
    for _ in range(54):
        pool.update(dt)

    assert entry.flags == 0x19
    assert entry.age == 0.9999997019767761

    pool.update(dt)
    assert entry.flags == 0


def test_effect_pool_update_runs_zero_dt_and_has_no_lifetime_epsilon() -> None:
    pool = EffectPool()
    expired_idx = pool.spawn(
        effect_id=0,
        pos=Vec2(),
        vel=Vec2(),
        rotation=0.0,
        scale=1.0,
        half_width=1.0,
        half_height=1.0,
        age=1.0,
        lifetime=1.0,
        flags=1,
        color=RGBA(),
        rotation_step=0.0,
        scale_step=0.0,
        detail_preset=5,
    )

    assert expired_idx == 0
    expired = pool.entries[expired_idx]
    pool.update(0.0)
    assert expired.flags == 0

    fade_idx = pool.spawn(
        effect_id=0,
        pos=Vec2(),
        vel=Vec2(),
        rotation=0.0,
        scale=1.0,
        half_width=1.0,
        half_height=1.0,
        age=0.0,
        lifetime=1e-12,
        flags=0x10,
        color=RGBA(1.0, 1.0, 1.0, 0.25),
        rotation_step=0.0,
        scale_step=0.0,
        detail_preset=5,
    )

    assert fade_idx == 0
    fading = pool.entries[fade_idx]
    pool.update(0.0)
    assert fading.flags == 0x10
    assert fading.color.a == 1.0


def test_spawn_blood_splatter_tags_exact_native_callers() -> None:
    pool = EffectPool()
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
    q = FxQueue()
    pool = EffectPool()

    pool.spawn_shell_casing(
        pos=Vec2(10.0, 20.0),
        aim_heading=0.0,
        draws=(0, 0, 0, 0),
        detail_preset=5,
    )

    active = pool.iter_active()
    assert len(active) == 1
    effect = active[0]
    assert effect.effect_id == 0x12
    assert effect.flags == 0x1C5
    assert effect.lifetime == f32(0.15)

    pool.update(0.2, fx_queue=q)
    assert q.count == 1
    assert effect.color.a == f32(0.35)

    entry = q.iter_active()[0]
    assert entry.effect_id == 0x12
    assert_float_close(entry.width, 4.0)
    assert_float_close(entry.height, 4.0)
    assert entry.color.a == f32(0.35)


def test_effect_pool_spawn_burst_matches_template_defaults() -> None:
    pool = EffectPool()

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
        assert entry.scale_step == f32(0.1)


def test_spawn_burst_tags_exact_native_callers() -> None:
    pool = EffectPool()
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
    pool = EffectPool()
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
    pool = EffectPool()

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
