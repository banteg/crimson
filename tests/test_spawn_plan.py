from __future__ import annotations

import math

from crimson.crand import Crand
from crimson.spawn_plan import SpawnEnv, build_spawn_plan
from crimson.spawn_templates import CreatureFlags, CreatureTypeId


def _step_msvcrt(state: int, n: int) -> int:
    for _ in range(n):
        state = (state * 0x343FD + 0x269EC3) & 0xFFFFFFFF
    return state


def test_spawn_plan_template_1_is_constant() -> None:
    rng = Crand(0x1234)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=False,
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(1, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.SPIDER_SP2
    assert c.flags == CreatureFlags.SPLIT_ON_DEATH
    assert c.size == 80.0
    assert c.health == 400.0
    assert c.max_health == 400.0
    assert c.move_speed == 2.0
    assert c.reward_value == 1000.0
    assert c.contact_damage == 17.0
    assert (c.tint_r, c.tint_g, c.tint_b, c.tint_a) == (0.8, 0.7, 0.4, 1.0)
    assert c.heading == 0.0

    # Rand consumption:
    # - creature_alloc_slot() for base: 1 rand
    # - base init random heading: 1 rand
    assert rng.state == _step_msvcrt(0x1234, 2)


def test_spawn_plan_template_0a_has_spawn_slot_and_non_hardcore_interval_bump() -> None:
    rng = Crand(0)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=False,
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x0A, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert len(plan.spawn_slots) == 1

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.flags == CreatureFlags.ANIM_PING_PONG
    assert c.spawn_slot == 0
    assert c.health == 1000.0
    assert c.max_health == 1000.0
    assert c.move_speed == 1.5
    assert c.size == 55.0
    assert (c.tint_r, c.tint_g, c.tint_b, c.tint_a) == (0.8, 0.7, 0.4, 1.0)
    assert c.contact_damage == 0.0

    slot = plan.spawn_slots[0]
    assert slot.owner_creature == 0
    assert slot.timer == 2.0
    assert slot.count == 0
    assert slot.limit == 100
    assert slot.child_template_id == 0x32
    # +0.2 happens in the tail when not hardcore and flags include 0x4.
    assert slot.interval == 5.2

    # Rand consumption: base alloc + base init random heading.
    assert rng.state == _step_msvcrt(0, 2)


def test_spawn_plan_template_0b_has_spawn_slot_and_non_hardcore_interval_bump() -> None:
    rng = Crand(0)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=False,
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x0B, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert len(plan.spawn_slots) == 1

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.flags == CreatureFlags.ANIM_PING_PONG
    assert c.spawn_slot == 0
    assert c.health == 3500.0
    assert c.max_health == 3500.0
    assert c.move_speed == 1.5
    assert c.size == 65.0
    assert (c.tint_r, c.tint_g, c.tint_b, c.tint_a) == (0.9, 0.1, 0.1, 1.0)
    assert c.contact_damage == 0.0

    slot = plan.spawn_slots[0]
    assert slot.timer == 2.0
    assert slot.limit == 100
    assert slot.child_template_id == 0x3C
    assert slot.interval == 6.2

    assert rng.state == _step_msvcrt(0, 2)


def test_spawn_plan_template_10_has_spawn_slot_and_non_hardcore_interval_bump() -> None:
    rng = Crand(0)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=False,
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x10, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert len(plan.spawn_slots) == 1

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.flags == CreatureFlags.ANIM_PING_PONG
    assert c.spawn_slot == 0
    assert c.health == 50.0
    assert c.max_health == 50.0
    assert c.move_speed == 2.8
    assert c.size == 32.0
    assert (c.tint_r, c.tint_g, c.tint_b, c.tint_a) == (0.9, 0.8, 0.4, 1.0)
    assert c.contact_damage == 0.0

    # 0x40133333 (float32) + 0.2 tail bump.
    slot = plan.spawn_slots[0]
    assert math.isclose(slot.interval, 2.499999952316284, abs_tol=1e-9)
    assert slot.child_template_id == 0x32

    assert rng.state == _step_msvcrt(0, 2)


def test_spawn_plan_template_12_spawns_formation_children() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x12, (100.0, 200.0), 0.0, rng, env)

    assert len(plan.creatures) == 9
    assert plan.primary == 8
    assert plan.spawn_slots == ()

    parent = plan.creatures[0]
    assert parent.type_id == CreatureTypeId.ALIEN
    assert parent.health == 200.0
    assert parent.max_health == 200.0
    assert parent.move_speed == 2.2
    assert parent.size == 55.0
    assert (parent.tint_r, parent.tint_g, parent.tint_b, parent.tint_a) == (0.65, 0.85, 0.97, 1.0)

    # Children are linked orbiters in a ring.
    for i, child in enumerate(plan.creatures[1:], start=0):
        assert child.type_id == CreatureTypeId.ALIEN
        assert child.ai_mode == 3
        assert child.ai_link_parent == 0
        assert child.health == 40.0
        assert child.max_health == 40.0
        assert child.move_speed == 2.4
        assert child.size == 50.0
        assert (child.tint_r, child.tint_g, child.tint_b, child.tint_a) == (0.32000002, 0.58800006, 0.426, 1.0)

        angle = float(i) * 0.7853982
        assert math.isclose(child.target_offset_x or 0.0, math.cos(angle) * 100.0, abs_tol=1e-4)
        assert math.isclose(child.target_offset_y or 0.0, math.sin(angle) * 100.0, abs_tol=1e-4)

    # Rand consumption:
    # - base alloc: 1
    # - base init random heading: 1
    # - 8 child allocs: 8
    assert rng.state == _step_msvcrt(0xBEEF, 10)


def test_spawn_plan_template_19_spawns_formation_children() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x19, (100.0, 200.0), 0.0, rng, env)

    assert len(plan.creatures) == 6
    assert plan.primary == 5
    assert plan.spawn_slots == ()

    parent = plan.creatures[0]
    assert parent.type_id == CreatureTypeId.ALIEN
    assert parent.health == 50.0
    assert parent.max_health == 50.0
    assert parent.move_speed == 3.8
    assert parent.size == 55.0
    assert (parent.tint_r, parent.tint_g, parent.tint_b, parent.tint_a) == (0.95, 0.55, 0.37, 1.0)

    for i, child in enumerate(plan.creatures[1:], start=0):
        assert child.type_id == CreatureTypeId.ALIEN
        assert child.ai_mode == 5
        assert child.ai_link_parent == 0
        assert child.health == 220.0
        assert child.max_health == 220.0
        assert child.move_speed == 3.8
        assert child.size == 50.0
        assert (child.tint_r, child.tint_g, child.tint_b, child.tint_a) == (0.7125, 0.41250002, 0.2775, 0.6)

        angle = float(i) * 1.2566371
        assert math.isclose(child.target_offset_x or 0.0, math.cos(angle) * 110.0, abs_tol=1e-4)
        assert math.isclose(child.target_offset_y or 0.0, math.sin(angle) * 110.0, abs_tol=1e-4)
        assert math.isclose(child.pos_x, 100.0 + (child.target_offset_x or 0.0), abs_tol=1e-4)
        assert math.isclose(child.pos_y, 200.0 + (child.target_offset_y or 0.0), abs_tol=1e-4)

    # Rand consumption:
    # - base alloc: 1
    # - base init random heading: 1
    # - 5 child allocs: 5
    assert rng.state == _step_msvcrt(0xBEEF, 7)
