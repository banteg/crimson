from __future__ import annotations

from crimson.effects import (
    FX_QUEUE_MAX_COUNT,
    EffectPool,
    FxQueue,
    FxQueueRotated,
    ParticlePool,
)
from crimson.effects_atlas import effect_src_rect
from crimson.math_parity import f32
from crimson.perks import PerkId
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


def test_fx_queue_rotated_applies_alpha_adjustment() -> None:
    q = FxQueueRotated()
    q.bodies_transparency = 2.0
    assert q.add(
        top_left=Vec2(),
        rgba=RGBA(1.0, 1.0, 1.0, 1.0),
        rotation=0.0,
        scale=64.0,
        creature_type_id=3,
    )
    entry = q.entries[0]
    assert_float_close(entry.color.a, 0.5)

    q.clear()
    q.bodies_transparency = 0.0
    assert q.add(
        top_left=Vec2(),
        rgba=RGBA(1.0, 1.0, 1.0, 1.0),
        rotation=0.0,
        scale=64.0,
        creature_type_id=3,
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


def test_particle_hit_applies_fire_damage() -> None:
    world = make_world()
    world.state.perks[int(PerkId.PYROMANIAC)] = 1
    creatures = place_creatures(world, [make_creature_state(pos=Vec2())])
    pool = ParticlePool()
    pool.spawn_particle(pos=Vec2(), angle=0.0, intensity=1.0, rng=world.state.rng)

    pool.update(0.016, step_runtime=make_step_runtime(world, dt=0.016))

    # intensity (1 - 0.016 * 0.9) * 10 fire damage, scaled x1.5 by Pyromaniac.
    assert_float_close(creatures[0].hp, f32(85.216))


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


def test_effect_pool_update_runs_zero_dt_and_has_no_lifetime_epsilon() -> None:
    pool = EffectPool()
    template = pool.template
    template.age = 1.0
    template.lifetime = 1.0
    template.flags = 1
    pool.spawn(0, Vec2(), 5)

    expired = pool.entries[0]
    pool.update(0.0)
    assert expired.flags == 0

    # The freed entry is back at the free-list head.
    template.age = 0.0
    template.lifetime = 1e-12
    template.flags = 0x10
    template.color = RGBA(1.0, 1.0, 1.0, 0.25)
    pool.spawn(0, Vec2(), 5)

    fading = pool.entries[0]
    pool.update(0.0)
    assert fading.flags == 0x10
    assert fading.color.a == 1.0


def test_effect_pool_shell_casing_queues_decal_on_expiry() -> None:
    q = FxQueue()
    pool = EffectPool()

    pool.spawn_shell_casing(
        pos=Vec2(10.0, 20.0),
        aim_heading=0.0,
        rng=ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST),
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
