from __future__ import annotations

import math

from crimson.creatures.runtime import CreatureState
from crimson.effects import EffectPool, FxQueue, FxQueueRotated, ParticlePool, SpriteEffectPool
from crimson.effects_atlas import effect_src_rect
from grim.geom import Vec2


class _SequenceRng:
    def __init__(self, values: list[int]) -> None:
        self._values = [int(value) for value in values]
        self._idx = 0

    def rand(self) -> int:
        if not self._values:
            return 0
        if self._idx >= len(self._values):
            return int(self._values[-1])
        value = int(self._values[self._idx])
        self._idx += 1
        return value


def test_effect_src_rect_uses_grid_and_frame() -> None:
    # effect_id 0x00: size_code 0x80 -> grid 2, frame 0x02 -> (col=0,row=1)
    rect = effect_src_rect(0x00, texture_width=200.0, texture_height=100.0)
    assert rect == (0.0, 50.0, 100.0, 50.0)


def test_fx_queue_caps_count() -> None:
    q = FxQueue(capacity=4, max_count=3)
    rgba = (1.0, 1.0, 1.0, 1.0)
    assert q.add(effect_id=0, pos=Vec2(), width=10.0, height=10.0, rotation=0.0, rgba=rgba)
    assert q.add(effect_id=0, pos=Vec2(), width=10.0, height=10.0, rotation=0.0, rgba=rgba)
    assert q.add(effect_id=0, pos=Vec2(), width=10.0, height=10.0, rotation=0.0, rgba=rgba)
    assert not q.add(effect_id=0, pos=Vec2(), width=10.0, height=10.0, rotation=0.0, rgba=rgba)
    assert q.count == 3


def test_fx_queue_rotated_applies_alpha_adjustment() -> None:
    q = FxQueueRotated(capacity=2, max_count=2)
    assert q.add(
        top_left=Vec2(),
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
        top_left=Vec2(),
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
    idx = pool.spawn(pos=Vec2(10.0, 20.0), vel=Vec2(2.0, -3.0), scale=1.0)
    fx = pool.entries[idx]
    assert fx.active
    assert fx.color_a == 1.0
    assert fx.rotation == 0.0

    pool.update(0.5)
    assert math.isclose(fx.pos.x, 11.0, abs_tol=1e-9)
    assert math.isclose(fx.pos.y, 18.5, abs_tol=1e-9)
    assert math.isclose(fx.rotation, 1.5, abs_tol=1e-9)
    assert math.isclose(fx.color_a, 0.5, abs_tol=1e-9)
    assert math.isclose(fx.scale, 31.0, abs_tol=1e-9)

    pool.update(0.6)
    assert not fx.active


def test_particle_pool_style_decay_rules_match_thresholds() -> None:
    pool = ParticlePool(size=2, rand=lambda: 0)

    # Style 0 persists until intensity <= 0.0.
    idx0 = pool.spawn_particle(pos=Vec2(), angle=0.0, intensity=1.0)
    p0 = pool.entries[idx0]
    p0.render_flag = False
    pool.update(1.0)
    assert p0.active
    assert math.isclose(p0.intensity, 0.1, abs_tol=1e-9)

    # Style 1 expires once intensity <= 0.8.
    idx1 = pool.spawn_particle(pos=Vec2(), angle=0.0, intensity=1.0)
    p1 = pool.entries[idx1]
    p1.render_flag = False
    p1.style_id = 1
    pool.update(1.0)
    assert not p1.active

    # Style 8 decays slowly and also uses the 0.8 cutoff.
    idx2 = pool.spawn_particle_slow(pos=Vec2(), angle=0.0)
    p2 = pool.entries[idx2]
    p2.render_flag = False
    pool.update(1.0)
    assert p2.active
    assert math.isclose(p2.intensity, 0.89, abs_tol=1e-9)


def test_particle_hit_deflects_rescales_spawns_fx_and_pushes_creature() -> None:
    # Rng consumption order:
    # - spawn_particle: spin
    # - update: random-walk jitter
    # - hit: speed_scale
    # - hit: sprite_vel_x, sprite_vel_y
    # - fx_queue.add_random: gray, w, rotation, effect_id
    rng = _SequenceRng([0, 50, 7, 0, 0, 0, 0, 0, 0])
    pool = ParticlePool(size=1, rand=rng.rand)
    fx_queue = FxQueue(capacity=1, max_count=1)
    sprite_effects = SpriteEffectPool(size=1, rand=lambda: 0)

    particle_id = pool.spawn_particle(pos=Vec2(), angle=0.0, intensity=1.0, owner_id=-1)
    particle = pool.entries[particle_id]

    creature = CreatureState()
    creature.active = True
    creature.hp = 100.0
    creature.pos = Vec2()
    creature.size = 50.0
    creature.hitbox_size = 16.0

    dt = 0.016
    pool.update(dt, creatures=[creature], fx_queue=fx_queue, sprite_effects=sprite_effects)

    assert particle.render_flag is False
    assert fx_queue.count == 1
    assert sprite_effects.entries[0].active
    assert math.isclose(sprite_effects.entries[0].color_a, 0.7, abs_tol=1e-9)

    deflect_step = math.tau * 0.2
    assert math.isclose(float(particle.angle), deflect_step, abs_tol=1e-6)

    speed_scale = 0.7
    expected_vel_x = math.cos(deflect_step) * 82.0 * speed_scale
    expected_vel_y = math.sin(deflect_step) * 82.0 * speed_scale
    assert math.isclose(float(particle.vel.x), expected_vel_x, abs_tol=1e-6)
    assert math.isclose(float(particle.vel.y), expected_vel_y, abs_tol=1e-6)

    assert math.isclose(float(creature.pos.x), expected_vel_x * dt, abs_tol=1e-6)
    assert math.isclose(float(creature.pos.y), expected_vel_y * dt, abs_tol=1e-6)


def test_effect_pool_blood_splatter_queues_decal_on_expiry() -> None:
    q = FxQueue(capacity=8, max_count=8)
    pool = EffectPool(size=8)

    pool.spawn_blood_splatter(
        pos=Vec2(10.0, 20.0),
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
    assert math.isclose(first.pos.x, 0.0, abs_tol=1e-9)
    assert math.isclose(first.pos.y, 20.0, abs_tol=1e-9)
    assert math.isclose(first.width, 2.0, abs_tol=1e-9)
    assert math.isclose(first.height, 2.0, abs_tol=1e-9)
    assert math.isclose(first.color_r, 1.0, abs_tol=1e-9)
    assert math.isclose(first.color_g, 1.0, abs_tol=1e-9)
    assert math.isclose(first.color_b, 1.0, abs_tol=1e-9)
    assert math.isclose(first.color_a, 0.8, abs_tol=1e-9)


def test_effect_pool_shell_casing_queues_decal_on_expiry() -> None:
    q = FxQueue(capacity=4, max_count=4)
    pool = EffectPool(size=4)

    pool.spawn_shell_casing(
        pos=Vec2(10.0, 20.0),
        aim_heading=0.0,
        weapon_flags=1,
        rand=lambda: 0,
        detail_preset=5,
    )

    active = pool.iter_active()
    assert len(active) == 1
    assert active[0].effect_id == 0x12
    assert active[0].flags == 0x1C5
    assert math.isclose(active[0].lifetime, 0.15, abs_tol=1e-9)

    pool.update(0.2, fx_queue=q)
    assert q.count == 1

    entry = q.iter_active()[0]
    assert entry.effect_id == 0x12
    assert math.isclose(entry.width, 4.0, abs_tol=1e-9)
    assert math.isclose(entry.height, 4.0, abs_tol=1e-9)
    assert math.isclose(entry.color_a, 0.35, abs_tol=1e-9)


def test_effect_pool_spawn_burst_matches_template_defaults() -> None:
    pool = EffectPool(size=8)

    pool.spawn_burst(
        pos=Vec2(10.0, 20.0),
        count=3,
        rand=lambda: 0,
        detail_preset=5,
    )

    active = pool.iter_active()
    assert len(active) == 3
    for entry in active:
        assert entry.effect_id == 0
        assert math.isclose(entry.half_width, 32.0, abs_tol=1e-9)
        assert math.isclose(entry.half_height, 32.0, abs_tol=1e-9)
        assert entry.flags == 0x1D
        assert math.isclose(entry.lifetime, 0.5, abs_tol=1e-9)
        assert math.isclose(entry.scale_step, 0.1, abs_tol=1e-9)


def test_effect_pool_spawn_ring_spawns_effect_1() -> None:
    pool = EffectPool(size=4)

    pool.spawn_ring(
        pos=Vec2(3.0, 4.0),
        detail_preset=5,
        color_r=0.6,
        color_g=0.6,
        color_b=1.0,
        color_a=1.0,
    )

    active = pool.iter_active()
    assert len(active) == 1
    entry = active[0]
    assert entry.effect_id == 1
    assert entry.flags == 0x19
    assert math.isclose(entry.pos.x, 3.0, abs_tol=1e-9)
    assert math.isclose(entry.pos.y, 4.0, abs_tol=1e-9)
    assert math.isclose(entry.lifetime, 0.25, abs_tol=1e-9)
    assert math.isclose(entry.scale_step, 50.0, abs_tol=1e-9)
