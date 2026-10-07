"""A full flame pool vs original projectile_update, including ordered hits."""

from __future__ import annotations

import pytest

from crimson.creatures.runtime import CreatureState
from crimson.math_parity import f32
from grim.color import RGBA
from grim.geom import Vec2
from tests.support.factories import make_step_runtime, world_with_creature

from ._support import (
    CREATURE_LAYOUT,
    CREATURE_STRIDE,
    PARTICLE_LAYOUT,
    PARTICLE_STRIDE,
    SPRITE_LAYOUT,
    SPRITE_STRIDE,
    Mismatch,
    compare_fields,
    mismatch_report,
    prepare_gameplay,
)


@pytest.mark.parametrize("hits,moving", [((), False), ((383,), False), ((5, 383), False), ((383,), True)])
def test_full_flame_pool_matches_native_first_collidable_slot(oracle, hits: tuple[int, ...], moving: bool) -> None:
    prepare_gameplay(oracle)
    oracle.write_u32("config_detail_preset", 5)
    dt = f32(0.016)
    oracle.write_f32("frame_dt", dt)
    world = world_with_creature(CreatureState())
    world.state.preserve_bugs = True
    seed = 0x464C414D
    oracle.rand_state = seed
    world.state.rng.srand(seed)
    creature_address = oracle.resolve("creature_pool")
    for index, creature in enumerate(world.creatures.entries):
        creature.active = True
        creature.hp = creature.max_hp = 1_000_000.0
        creature.size = 32.0
        creature.tint = RGBA(1.0, 1.0, 1.0, 1.0)
        creature.pos = Vec2(128.0 + index % 16 * 48.0, 128.0 + index // 16 * 24.0)
        if index in hits or index == 1:
            creature.pos = Vec2(43.0, 40.0)
        if moving and index in hits:
            creature.pos = Vec2(f32(63.99), 40.0)
            creature.size = 350.0
        if index == 1:
            creature.death_timer = 5.0  # Earlier overlapping corpse must be skipped.
        fields = {
            "active": 1, "health": creature.hp, "max_health": creature.max_hp,
            "pos_x": creature.pos.x, "pos_y": creature.pos.y, "size": creature.size,
            "death_timer": creature.death_timer, "type_id": int(creature.type_id),
            "tint_r": 1.0, "tint_g": 1.0, "tint_b": 1.0, "tint_a": 1.0,
        }
        for name, value in fields.items():
            offset, fmt = CREATURE_LAYOUT[name]
            if fmt == "f":
                oracle.write_f32(creature_address + index * CREATURE_STRIDE + offset, value)
            else:
                oracle.write(creature_address + index * CREATURE_STRIDE + offset, int(value).to_bytes(1 if fmt == "B" else 4, "little"))
    position = Vec2(40.0, 40.0)
    position_address = oracle.alloc_f32s(position.x, position.y)
    for index in range(128):
        angle = 0.0 if moving else f32(index * 0.01)
        if moving and index == 100:
            position = Vec2(128.0, 40.0)
            position_address = oracle.alloc_f32s(position.x, position.y)
        native_index = oracle.call("fx_spawn_particle", position_address, angle, 0, 1.0).eax
        assert native_index == world.state.particles.spawn_particle(pos=position, angle=angle, rng=world.state.rng)
    oracle.call("projectile_update")
    step = make_step_runtime(world, dt=dt)
    world.projectile_update(step)
    if moving:
        assert world.creatures.entries[383].pos.x >= 64.0
        assert not world.state.particles.entries[127].in_flight, world.creatures.entries[383].pos
    mismatches: list[Mismatch] = []
    particle_address = oracle.resolve("particle_pool")
    layout = {**PARTICLE_LAYOUT, "in_flight": (1, "B"), "rotation": (0x2C, "f")}
    for index, particle in enumerate(world.state.particles.entries):
        address = particle_address + index * PARTICLE_STRIDE
        mismatches += compare_fields(str(index), oracle.read_fields(address, layout), {
            "active": int(particle.active), "in_flight": int(particle.in_flight),
            "pos_x": particle.pos.x, "pos_y": particle.pos.y, "vel_x": particle.vel.x, "vel_y": particle.vel.y,
            "intensity": particle.intensity, "angle": particle.angle, "rotation": particle.rotation,
            "style_id": int(particle.style_id),
        }, address=address)
    for index, creature in enumerate(world.creatures.entries):
        address = creature_address + index * CREATURE_STRIDE
        mismatches += compare_fields(f"creature {index}", oracle.read_fields(address, CREATURE_LAYOUT), {
            "health": creature.hp, "tint_r": creature.tint.r, "tint_g": creature.tint.g, "tint_b": creature.tint.b,
        }, address=address)
    sprite_address = oracle.resolve("sprite_effect_pool")
    for index, sprite in enumerate(world.state.sprite_effects.entries):
        address = sprite_address + index * SPRITE_STRIDE
        native = oracle.read_fields(address, SPRITE_LAYOUT)
        if native["active"] or sprite.active:
            mismatches += compare_fields(f"sprite {index}", native, {
                "active": int(sprite.active), "color_r": sprite.color.r, "color_g": sprite.color.g,
                "color_b": sprite.color.b, "color_a": sprite.color.a, "rotation": sprite.rotation,
                "pos_x": sprite.pos.x, "pos_y": sprite.pos.y, "vel_x": sprite.vel.x, "vel_y": sprite.vel.y, "scale": sprite.scale,
            }, address=address)
    assert oracle.rand_state == world.state.rng.state
    assert oracle.read_u32("fx_queue_count") == step.fx_queue.count
    assert not mismatches, mismatch_report(mismatches, total_cases=1)
