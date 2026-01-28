from __future__ import annotations

import math

from crimson.effects import EffectPool, FxQueue, FxQueueRotated, ParticlePool, SpriteEffectPool
from crimson.effects_atlas import effect_src_rect


def test_effect_src_rect_uses_grid_and_frame() -> None:
    # effect_id 0x00: size_code 0x80 -> grid 2, frame 0x02 -> (col=0,row=1)
    rect = effect_src_rect(0x00, texture_width=200.0, texture_height=100.0)
    assert rect == (0.0, 50.0, 100.0, 50.0)


def test_fx_queue_caps_count() -> None:
    q = FxQueue(capacity=4, max_count=3)
    rgba = (1.0, 1.0, 1.0, 1.0)
    assert q.add(effect_id=0, pos_x=0.0, pos_y=0.0, width=10.0, height=10.0, rotation=0.0, rgba=rgba)
    assert q.add(effect_id=0, pos_x=0.0, pos_y=0.0, width=10.0, height=10.0, rotation=0.0, rgba=rgba)
    assert q.add(effect_id=0, pos_x=0.0, pos_y=0.0, width=10.0, height=10.0, rotation=0.0, rgba=rgba)
    assert not q.add(effect_id=0, pos_x=0.0, pos_y=0.0, width=10.0, height=10.0, rotation=0.0, rgba=rgba)
    assert q.count == 3


def test_fx_queue_rotated_applies_alpha_adjustment() -> None:
    q = FxQueueRotated(capacity=2, max_count=2)
    assert q.add(
        top_left_x=0.0,
        top_left_y=0.0,
        rgba=(1.0, 1.0, 1.0, 1.0),
        rotation=0.0,
        scale=64.0,
        creature_type_id=3,
        terrain_bodies_transparency=2.0,
    )
    entry = q.entries[0]
    assert math.isclose(entry.color_a, 0.5, abs_tol=1e-9)

    q.clear()
    assert q.add(
        top_left_x=0.0,
        top_left_y=0.0,
        rgba=(1.0, 1.0, 1.0, 1.0),
        rotation=0.0,
        scale=64.0,
        creature_type_id=3,
        terrain_bodies_transparency=0.0,
    )
    entry = q.entries[0]
    assert math.isclose(entry.color_a, 0.8, abs_tol=1e-9)


def test_sprite_effect_pool_updates_and_expires() -> None:
    pool = SpriteEffectPool(size=1, rand=lambda: 0)
    idx = pool.spawn(pos_x=10.0, pos_y=20.0, vel_x=2.0, vel_y=-3.0, scale=1.0)
    fx = pool.entries[idx]
    assert fx.active
    assert fx.color_a == 1.0
    assert fx.rotation == 0.0

    pool.update(0.5)
    assert math.isclose(fx.pos_x, 11.0, abs_tol=1e-9)
    assert math.isclose(fx.pos_y, 18.5, abs_tol=1e-9)
    assert math.isclose(fx.rotation, 1.5, abs_tol=1e-9)
    assert math.isclose(fx.color_a, 0.5, abs_tol=1e-9)
    assert math.isclose(fx.scale, 31.0, abs_tol=1e-9)

    pool.update(0.6)
    assert not fx.active


def test_particle_pool_style_decay_rules_match_thresholds() -> None:
    pool = ParticlePool(size=2, rand=lambda: 0)

    # Style 0 persists until intensity <= 0.0.
    idx0 = pool.spawn_particle(pos_x=0.0, pos_y=0.0, angle=0.0, intensity=1.0)
    p0 = pool.entries[idx0]
    p0.render_flag = False
    pool.update(1.0)
    assert p0.active
    assert math.isclose(p0.intensity, 0.1, abs_tol=1e-9)

    # Style 1 expires once intensity <= 0.8.
    idx1 = pool.spawn_particle(pos_x=0.0, pos_y=0.0, angle=0.0, intensity=1.0)
    p1 = pool.entries[idx1]
    p1.render_flag = False
    p1.style_id = 1
    pool.update(1.0)
    assert not p1.active

    # Style 8 decays slowly and also uses the 0.8 cutoff.
    idx2 = pool.spawn_particle_slow(pos_x=0.0, pos_y=0.0, angle=0.0)
    p2 = pool.entries[idx2]
    p2.render_flag = False
    pool.update(1.0)
    assert p2.active
    assert math.isclose(p2.intensity, 0.89, abs_tol=1e-9)


def test_effect_pool_blood_splatter_queues_decal_on_expiry() -> None:
    q = FxQueue(capacity=8, max_count=8)
    pool = EffectPool(size=8)

    pool.spawn_blood_splatter(
        pos_x=10.0,
        pos_y=20.0,
        angle=0.0,
        age=0.0,
        rand=lambda: 0,
        detail_preset=5,
        fx_toggle=0,
    )

    assert len(pool.iter_active()) == 2
    assert q.count == 0

    pool.update(0.1, fx_queue=q)
    assert q.count == 0

    pool.update(0.2, fx_queue=q)
    assert q.count == 2

    first = q.iter_active()[0]
    assert first.effect_id == 7
    assert math.isclose(first.pos_x, 0.0, abs_tol=1e-9)
    assert math.isclose(first.pos_y, 20.0, abs_tol=1e-9)
    assert math.isclose(first.width, 2.0, abs_tol=1e-9)
    assert math.isclose(first.height, 2.0, abs_tol=1e-9)
    assert math.isclose(first.color_r, 1.0, abs_tol=1e-9)
    assert math.isclose(first.color_g, 1.0, abs_tol=1e-9)
    assert math.isclose(first.color_b, 1.0, abs_tol=1e-9)
    assert math.isclose(first.color_a, 0.8, abs_tol=1e-9)
