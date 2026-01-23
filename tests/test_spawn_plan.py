from __future__ import annotations

import math
import struct

from crimson.crand import Crand
from crimson.creatures.spawn import CreatureFlags, CreatureTypeId, SpawnEnv, build_spawn_plan


def _step_msvcrt(state: int, n: int) -> int:
    for _ in range(n):
        state = (state * 0x343FD + 0x269EC3) & 0xFFFFFFFF
    return state


def _msvcrt_rand(state: int) -> tuple[int, int]:
    """Return (new_state, rand_output) for MSVCRT rand()."""
    state = (state * 0x343FD + 0x269EC3) & 0xFFFFFFFF
    return state, (state >> 16) & 0x7FFF


def _f32(u32: int) -> float:
    return struct.unpack("<f", struct.pack("<I", u32 & 0xFFFFFFFF))[0]


def test_spawn_plan_template_00_has_spawn_slot_and_non_hardcore_interval_bump() -> None:
    rng = Crand(0)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x00, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert len(plan.spawn_slots) == 1

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ZOMBIE
    assert c.flags == (CreatureFlags.ANIM_PING_PONG | CreatureFlags.ANIM_LONG_STRIP)
    assert c.spawn_slot == 0
    assert c.size == 64.0
    assert c.health == 8500.0
    assert c.max_health == 8500.0
    assert c.move_speed == 1.3
    assert c.reward_value == 6600.0
    assert c.contact_damage == 50.0
    assert (c.tint_r, c.tint_g, c.tint_b, c.tint_a) == (0.6, 0.6, 1.0, 0.8)
    assert c.heading == 0.0

    slot = plan.spawn_slots[0]
    assert slot.owner_creature == 0
    assert slot.timer == 1.0
    assert slot.count == 0
    assert slot.limit == 0x32C
    assert slot.child_template_id == 0x41
    assert math.isclose(slot.interval, _f32(0x3F333333) + 0.2, abs_tol=1e-9)

    assert rng.state == _step_msvcrt(0, 2)


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


def test_spawn_plan_template_03_is_randomized_and_tail_enables_ai7_timer() -> None:
    seed = 0xBEEF
    rng = Crand(seed)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x03, (100.0, 200.0), -100.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    state = seed
    state, _ = _msvcrt_rand(state)  # alloc phase_seed
    state, r_heading = _msvcrt_rand(state)  # final heading
    expected_heading = float(r_heading % 0x274) * 0.01
    state, _ = _msvcrt_rand(state)  # base init random heading (overwritten)

    state, r_size = _msvcrt_rand(state)
    expected_size = float(r_size % 0xF + 0x26)
    expected_health = expected_size * 1.1428572 + 20.0
    expected_reward = expected_size + expected_size + 50.0

    state, r_speed = _msvcrt_rand(state)
    expected_speed_pre_tail = float(r_speed % 0x12) * 0.1 + 1.1

    state, r_tint_b = _msvcrt_rand(state)
    expected_tint_b = float(r_tint_b % 0x19) * 0.01 + 0.8
    expected_tint_b = min(max(expected_tint_b, 0.0), 1.0)

    state, r_contact = _msvcrt_rand(state)
    expected_contact = float(r_contact % 10) + 4.0

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.SPIDER_SP1
    assert c.flags == CreatureFlags.AI7_LINK_TIMER
    assert c.ai_timer == 0
    assert c.size == expected_size
    assert c.health == expected_health
    assert c.max_health == expected_health
    assert c.reward_value == expected_reward
    assert c.contact_damage == expected_contact
    assert (c.tint_r, c.tint_g, c.tint_b, c.tint_a) == (0.6, 0.6, expected_tint_b, 1.0)
    assert math.isclose(c.move_speed or 0.0, expected_speed_pre_tail * 1.2, abs_tol=1e-9)
    assert c.heading == expected_heading

    assert rng.state == _step_msvcrt(seed, 7)


def test_spawn_plan_template_04_is_randomized() -> None:
    seed = 0xBEEF
    rng = Crand(seed)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x04, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    state = seed
    state, _ = _msvcrt_rand(state)  # alloc phase_seed
    state, _ = _msvcrt_rand(state)  # base init random heading

    state, r_size = _msvcrt_rand(state)
    expected_size = float(r_size % 0xF + 0x26)
    expected_health = expected_size * 1.1428572 + 20.0
    expected_reward = expected_size + expected_size + 50.0

    state, r_speed = _msvcrt_rand(state)
    expected_speed = float(r_speed % 0x12) * 0.1 + 1.1

    state, r_contact = _msvcrt_rand(state)
    expected_contact = float(r_contact % 10) + 4.0

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.LIZARD
    assert c.size == expected_size
    assert c.health == expected_health
    assert c.max_health == expected_health
    assert c.move_speed == expected_speed
    assert c.reward_value == expected_reward
    assert c.contact_damage == expected_contact
    assert (c.tint_r, c.tint_g, c.tint_b, c.tint_a) == (0.67, 0.67, 1.0, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(seed, 5)


def test_spawn_plan_template_05_is_randomized() -> None:
    seed = 0xBEEF
    rng = Crand(seed)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x05, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    state = seed
    state, _ = _msvcrt_rand(state)  # alloc phase_seed
    state, _ = _msvcrt_rand(state)  # base init random heading

    state, r_size = _msvcrt_rand(state)
    expected_size = float(r_size % 0xF + 0x26)
    expected_health = expected_size * 1.1428572 + 20.0
    expected_reward = expected_size + expected_size + 50.0

    state, r_speed = _msvcrt_rand(state)
    expected_speed = float(r_speed % 0x12) * 0.1 + 1.1

    state, r_tint_b = _msvcrt_rand(state)
    expected_tint_b = float(r_tint_b % 0x19) * 0.01 + 0.8
    expected_tint_b = min(max(expected_tint_b, 0.0), 1.0)

    state, r_contact = _msvcrt_rand(state)
    expected_contact = float(r_contact % 10) + 4.0

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.SPIDER_SP2
    assert c.size == expected_size
    assert c.health == expected_health
    assert c.max_health == expected_health
    assert c.move_speed == expected_speed
    assert c.reward_value == expected_reward
    assert c.contact_damage == expected_contact
    assert (c.tint_r, c.tint_g, c.tint_b, c.tint_a) == (0.6, 0.6, expected_tint_b, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(seed, 6)


def test_spawn_plan_template_06_is_randomized() -> None:
    seed = 0xBEEF
    rng = Crand(seed)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x06, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    state = seed
    state, _ = _msvcrt_rand(state)  # alloc phase_seed
    state, _ = _msvcrt_rand(state)  # base init random heading

    state, r_size = _msvcrt_rand(state)
    expected_size = float(r_size % 0xF + 0x26)
    expected_health = expected_size * 1.1428572 + 20.0
    expected_reward = expected_size + expected_size + 50.0

    state, r_speed = _msvcrt_rand(state)
    expected_speed = float(r_speed % 0x12) * 0.1 + 1.1

    state, r_tint_b = _msvcrt_rand(state)
    expected_tint_b = float(r_tint_b % 0x19) * 0.01 + 0.8
    expected_tint_b = min(max(expected_tint_b, 0.0), 1.0)

    state, r_contact = _msvcrt_rand(state)
    expected_contact = float(r_contact % 10) + 4.0

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.size == expected_size
    assert c.health == expected_health
    assert c.max_health == expected_health
    assert c.move_speed == expected_speed
    assert c.reward_value == expected_reward
    assert c.contact_damage == expected_contact
    assert (c.tint_r, c.tint_g, c.tint_b, c.tint_a) == (0.6, 0.6, expected_tint_b, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(seed, 6)


def test_spawn_plan_template_07_has_spawn_slot_and_non_hardcore_interval_bump() -> None:
    rng = Crand(0)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=False,
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x07, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert len(plan.spawn_slots) == 1

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.flags == CreatureFlags.ANIM_PING_PONG
    assert c.spawn_slot == 0
    assert c.health == 1000.0
    assert c.max_health == 1000.0
    assert c.move_speed == 2.0
    assert c.reward_value == 3000.0
    assert c.size == 50.0
    assert (c.tint_r, c.tint_g, c.tint_b, c.tint_a) == (1.0, 1.0, 1.0, 1.0)
    assert c.contact_damage == 0.0

    slot = plan.spawn_slots[0]
    assert slot.timer == 1.0
    assert slot.limit == 100
    assert slot.child_template_id == 0x1D
    # 0x400ccccd (float32) + 0.2 tail bump.
    assert math.isclose(slot.interval, 2.400000047683716, abs_tol=1e-9)

    assert rng.state == _step_msvcrt(0, 2)


def test_spawn_plan_template_08_has_spawn_slot_and_non_hardcore_interval_bump() -> None:
    rng = Crand(0)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=False,
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x08, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert len(plan.spawn_slots) == 1

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.flags == CreatureFlags.ANIM_PING_PONG
    assert c.spawn_slot == 0
    assert c.health == 1000.0
    assert c.max_health == 1000.0
    assert c.move_speed == 2.0
    assert c.reward_value == 3000.0
    assert c.size == 50.0
    assert (c.tint_r, c.tint_g, c.tint_b, c.tint_a) == (1.0, 1.0, 1.0, 1.0)
    assert c.contact_damage == 0.0

    slot = plan.spawn_slots[0]
    assert slot.timer == 1.0
    assert slot.limit == 100
    assert slot.child_template_id == 0x1D
    # 0x40333333 (float32) + 0.2 tail bump.
    assert math.isclose(slot.interval, 2.999999952316284, abs_tol=1e-9)

    assert rng.state == _step_msvcrt(0, 2)


def test_spawn_plan_template_09_has_spawn_slot_and_non_hardcore_interval_bump() -> None:
    rng = Crand(0)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=False,
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x09, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert len(plan.spawn_slots) == 1

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.flags == CreatureFlags.ANIM_PING_PONG
    assert c.spawn_slot == 0
    assert c.health == 450.0
    assert c.max_health == 450.0
    assert c.move_speed == 2.0
    assert c.reward_value == 1000.0
    assert c.size == 40.0
    assert (c.tint_r, c.tint_g, c.tint_b, c.tint_a) == (1.0, 1.0, 1.0, 1.0)
    assert c.contact_damage == 0.0

    slot = plan.spawn_slots[0]
    assert slot.timer == 1.0
    assert slot.limit == 0x10
    assert slot.child_template_id == 0x1D
    assert slot.interval == 2.2

    assert rng.state == _step_msvcrt(0, 2)


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


def test_spawn_plan_template_0c_has_spawn_slot_and_non_hardcore_interval_bump() -> None:
    rng = Crand(0)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=False,
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x0C, (100.0, 200.0), 0.0, rng, env)

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
    assert c.reward_value == 1000.0
    assert c.size == 32.0
    assert (c.tint_r, c.tint_g, c.tint_b, c.tint_a) == (0.9, 0.8, 0.4, 1.0)
    assert c.contact_damage == 0.0

    slot = plan.spawn_slots[0]
    assert slot.timer == 1.5
    assert slot.limit == 100
    assert slot.child_template_id == 0x31
    assert slot.interval == 2.2

    assert rng.state == _step_msvcrt(0, 2)


def test_spawn_plan_template_0d_has_spawn_slot_and_non_hardcore_interval_bump() -> None:
    rng = Crand(0)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=False,
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x0D, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert len(plan.spawn_slots) == 1

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.flags == CreatureFlags.ANIM_PING_PONG
    assert c.spawn_slot == 0
    assert c.health == 50.0
    assert c.max_health == 50.0
    assert c.move_speed == 1.3
    assert c.reward_value == 1000.0
    assert c.size == 32.0
    assert (c.tint_r, c.tint_g, c.tint_b, c.tint_a) == (0.9, 0.8, 0.4, 1.0)
    assert c.contact_damage == 0.0

    slot = plan.spawn_slots[0]
    assert slot.timer == 2.0
    assert slot.limit == 100
    assert slot.child_template_id == 0x31
    assert slot.interval == 6.2

    assert rng.state == _step_msvcrt(0, 2)


def test_spawn_plan_template_0f_is_constant() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x0F, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.health == 20.0
    assert c.max_health == 20.0
    assert c.move_speed == _f32(0x4039999A)
    assert c.reward_value == 60.0
    assert c.size == 50.0
    assert c.contact_damage == 35.0
    assert (c.tint_r, c.tint_g, c.tint_b, c.tint_a) == (
        _f32(0x3F2A3D70),
        _f32(0x3EC51EB8),
        _f32(0x3E849BA6),
        _f32(0x3F0F5C29),
    )
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(0xBEEF, 2)


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
        # The original falls through a debug "Unhandled creatureType.\n" block, overwriting
        # the return creature's health to 20.0 (primary == last child).
        expected_health = 20.0 if i == 7 else 40.0
        assert child.health == expected_health
        assert child.max_health == expected_health
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
        expected_health = 20.0 if i == 4 else 220.0
        assert child.health == expected_health
        assert child.max_health == expected_health
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


def test_spawn_plan_template_1a_is_randomized_tint() -> None:
    seed = 0xBEEF
    rng = Crand(seed)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x1A, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    state = seed
    state, _ = _msvcrt_rand(state)  # alloc phase_seed
    state, _ = _msvcrt_rand(state)  # base init random heading
    state, r_tint = _msvcrt_rand(state)
    expected_tint = float(r_tint % 40) * 0.01 + 0.5

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.ai_mode == 1
    assert c.size == 50.0
    assert c.health == 50.0
    assert c.max_health == 50.0
    assert c.move_speed == 2.4
    assert c.reward_value == 125.0
    assert c.contact_damage == 5.0
    assert (c.tint_r, c.tint_g, c.tint_b, c.tint_a) == (expected_tint, expected_tint, 1.0, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(seed, 3)


def test_spawn_plan_template_1b_is_randomized_tint_and_tail_enables_ai7_timer() -> None:
    seed = 0xBEEF
    rng = Crand(seed)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x1B, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    state = seed
    state, _ = _msvcrt_rand(state)  # alloc phase_seed
    state, _ = _msvcrt_rand(state)  # base init random heading
    state, r_tint = _msvcrt_rand(state)
    expected_tint = float(r_tint % 40) * 0.01 + 0.5

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.SPIDER_SP1
    assert c.ai_mode == 1
    assert c.flags == CreatureFlags.AI7_LINK_TIMER
    assert c.ai_timer == 0
    assert c.size == 50.0
    assert c.health == 40.0
    assert c.max_health == 40.0
    assert math.isclose(c.move_speed or 0.0, 2.4 * 1.2, abs_tol=1e-9)
    assert c.reward_value == 125.0
    assert c.contact_damage == 5.0
    assert (c.tint_r, c.tint_g, c.tint_b, c.tint_a) == (expected_tint, expected_tint, 1.0, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(seed, 3)


def test_spawn_plan_template_1c_is_randomized_tint() -> None:
    seed = 0xBEEF
    rng = Crand(seed)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x1C, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    state = seed
    state, _ = _msvcrt_rand(state)  # alloc phase_seed
    state, _ = _msvcrt_rand(state)  # base init random heading
    state, r_tint = _msvcrt_rand(state)
    expected_tint = float(r_tint % 40) * 0.01 + 0.5

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.LIZARD
    assert c.ai_mode == 1
    assert c.size == 50.0
    assert c.health == 50.0
    assert c.max_health == 50.0
    assert c.move_speed == 2.4
    assert c.reward_value == 125.0
    assert c.contact_damage == 5.0
    assert (c.tint_r, c.tint_g, c.tint_b, c.tint_a) == (expected_tint, expected_tint, 1.0, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(seed, 3)


def test_spawn_plan_template_1d_is_randomized() -> None:
    seed = 0xBEEF
    rng = Crand(seed)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x1D, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    state = seed
    state, _ = _msvcrt_rand(state)  # alloc phase_seed
    state, _ = _msvcrt_rand(state)  # base init random heading

    state, r_size = _msvcrt_rand(state)
    expected_size = float(r_size % 20 + 35)
    expected_health = expected_size * 1.1428572 + 10.0

    state, r_speed = _msvcrt_rand(state)
    expected_speed = float(r_speed % 15) * 0.1 + 1.1

    state, r_reward = _msvcrt_rand(state)
    expected_reward = float(r_reward % 100 + 50)

    state, r_tint_r = _msvcrt_rand(state)
    expected_tint_r = float(r_tint_r % 50) * 0.001 + 0.60000002

    state, r_tint_g = _msvcrt_rand(state)
    expected_tint_g = float(r_tint_g % 50) * 0.0099999998 + 0.5

    state, r_tint_b = _msvcrt_rand(state)
    expected_tint_b = float(r_tint_b % 50) * 0.001 + 0.60000002

    state, r_contact = _msvcrt_rand(state)
    expected_contact = float(r_contact % 10) + 4.0

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.size == expected_size
    assert c.health == expected_health
    assert c.max_health == expected_health
    assert c.move_speed == expected_speed
    assert c.reward_value == expected_reward
    assert c.contact_damage == expected_contact
    assert (c.tint_r, c.tint_g, c.tint_b, c.tint_a) == (expected_tint_r, expected_tint_g, expected_tint_b, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(seed, 9)


def test_spawn_plan_template_1e_is_randomized() -> None:
    seed = 0xBEEF
    rng = Crand(seed)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x1E, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    state = seed
    state, _ = _msvcrt_rand(state)  # alloc phase_seed
    state, _ = _msvcrt_rand(state)  # base init random heading

    state, r_size = _msvcrt_rand(state)
    expected_size = float(r_size % 30 + 35)
    expected_health = expected_size * 2.2857144 + 10.0

    state, r_speed = _msvcrt_rand(state)
    expected_speed = float(r_speed % 17) * 0.1 + 1.5

    state, r_reward = _msvcrt_rand(state)
    expected_reward = float(r_reward % 200 + 50)

    state, r_tint_r = _msvcrt_rand(state)
    expected_tint_r = float(r_tint_r % 50) * 0.001 + 0.60000002

    state, r_tint_g = _msvcrt_rand(state)
    expected_tint_g = float(r_tint_g % 50) * 0.001 + 0.60000002

    state, r_tint_b = _msvcrt_rand(state)
    expected_tint_b = float(r_tint_b % 50) * 0.0099999998 + 0.5

    state, r_contact = _msvcrt_rand(state)
    expected_contact = float(r_contact % 30) + 4.0

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.size == expected_size
    assert c.health == expected_health
    assert c.max_health == expected_health
    assert c.move_speed == expected_speed
    assert c.reward_value == expected_reward
    assert c.contact_damage == expected_contact
    assert (c.tint_r, c.tint_g, c.tint_b, c.tint_a) == (expected_tint_r, expected_tint_g, expected_tint_b, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(seed, 9)


def test_spawn_plan_template_1f_is_randomized() -> None:
    seed = 0xBEEF
    rng = Crand(seed)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x1F, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    state = seed
    state, _ = _msvcrt_rand(state)  # alloc phase_seed
    state, _ = _msvcrt_rand(state)  # base init random heading

    state, r_size = _msvcrt_rand(state)
    expected_size = float(r_size % 30 + 45)
    expected_health = expected_size * 3.7142856 + 30.0

    state, r_speed = _msvcrt_rand(state)
    expected_speed = float(r_speed % 21) * 0.1 + 1.6

    state, r_reward = _msvcrt_rand(state)
    expected_reward = float(r_reward % 200 + 80)

    state, r_tint_r = _msvcrt_rand(state)
    expected_tint_r = float(r_tint_r % 50) * 0.0099999998 + 0.5

    state, r_tint_g = _msvcrt_rand(state)
    expected_tint_g = float(r_tint_g % 50) * 0.001 + 0.60000002

    state, r_tint_b = _msvcrt_rand(state)
    expected_tint_b = float(r_tint_b % 50) * 0.001 + 0.60000002

    state, r_contact = _msvcrt_rand(state)
    expected_contact = float(r_contact % 35) + 8.0

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.size == expected_size
    assert c.health == expected_health
    assert c.max_health == expected_health
    assert c.move_speed == expected_speed
    assert c.reward_value == expected_reward
    assert c.contact_damage == expected_contact
    assert (c.tint_r, c.tint_g, c.tint_b, c.tint_a) == (expected_tint_r, expected_tint_g, expected_tint_b, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(seed, 9)


def test_spawn_plan_template_20_is_randomized() -> None:
    seed = 0xBEEF
    rng = Crand(seed)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x20, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    state = seed
    state, _ = _msvcrt_rand(state)  # alloc phase_seed
    state, _ = _msvcrt_rand(state)  # base init random heading

    state, r_size = _msvcrt_rand(state)
    expected_size = float(r_size % 30 + 40)
    expected_health = expected_size * 1.1428572 + 20.0

    state, r_speed = _msvcrt_rand(state)
    expected_speed = float(r_speed % 18) * 0.1 + 1.1
    expected_reward = expected_size + expected_size + 50.0

    state, r_tint_g = _msvcrt_rand(state)
    expected_tint_g = float(r_tint_g % 40) * 0.0099999998 + 0.60000002

    state, r_contact = _msvcrt_rand(state)
    expected_contact = float(r_contact % 10) + 4.0

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.size == expected_size
    assert c.health == expected_health
    assert c.max_health == expected_health
    assert c.move_speed == expected_speed
    assert c.reward_value == expected_reward
    assert c.contact_damage == expected_contact
    assert (c.tint_r, c.tint_g, c.tint_b, c.tint_a) == (_f32(0x3E99999A), expected_tint_g, _f32(0x3E99999A), 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(seed, 6)


def test_spawn_plan_template_24_is_constant() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x24, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.health == 20.0
    assert c.max_health == 20.0
    assert c.move_speed == 2.0
    assert c.reward_value == 110.0
    assert c.size == 50.0
    assert c.contact_damage == 4.0
    assert (c.tint_r, c.tint_g, c.tint_b, c.tint_a) == (0.1, 0.7, 0.11, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(0xBEEF, 2)


def test_spawn_plan_template_25_is_constant() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x25, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.health == 25.0
    assert c.max_health == 25.0
    assert c.move_speed == 2.5
    assert c.reward_value == 125.0
    assert c.size == 30.0
    assert c.contact_damage == 3.0
    assert (c.tint_r, c.tint_g, c.tint_b, c.tint_a) == (0.1, 0.8, 0.11, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(0xBEEF, 2)


def test_spawn_plan_template_34_is_randomized_and_tail_enables_ai7_timer() -> None:
    seed = 0xBEEF
    rng = Crand(seed)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x34, (100.0, 200.0), -100.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    state = seed
    state, _ = _msvcrt_rand(state)  # alloc phase_seed
    state, r_heading = _msvcrt_rand(state)  # final heading
    expected_heading = float(r_heading % 0x274) * 0.01
    state, _ = _msvcrt_rand(state)  # base init random heading (overwritten)

    state, r_size = _msvcrt_rand(state)
    expected_size = float(r_size % 0x14 + 0x28)
    expected_health = expected_size * 1.1428572 + 20.0

    state, r_speed = _msvcrt_rand(state)
    expected_speed_pre_tail = float(r_speed % 0x12) * 0.1 + 1.1
    expected_reward = expected_size + expected_size + 50.0

    state, r_tint = _msvcrt_rand(state)
    expected_tint_g = float(r_tint % 0x28) * 0.01 + 0.6

    state, r_contact = _msvcrt_rand(state)
    expected_contact = float(r_contact % 10) + 4.0

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.SPIDER_SP1
    assert c.flags == CreatureFlags.AI7_LINK_TIMER
    assert c.ai_timer == 0
    assert c.size == expected_size
    assert c.health == expected_health
    assert c.max_health == expected_health
    assert c.reward_value == expected_reward
    assert c.contact_damage == expected_contact
    assert (c.tint_r, c.tint_g, c.tint_b, c.tint_a) == (0.5, expected_tint_g, 0.5, 1.0)
    assert math.isclose(c.move_speed or 0.0, expected_speed_pre_tail * 1.2, abs_tol=1e-9)
    assert c.heading == expected_heading

    assert rng.state == _step_msvcrt(seed, 7)


def test_spawn_plan_template_35_is_randomized() -> None:
    seed = 0xBEEF
    rng = Crand(seed)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x35, (100.0, 200.0), -100.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    state = seed
    state, _ = _msvcrt_rand(state)  # alloc phase_seed
    state, r_heading = _msvcrt_rand(state)  # final heading
    expected_heading = float(r_heading % 0x274) * 0.01
    state, _ = _msvcrt_rand(state)  # base init random heading (overwritten)

    state, r_size = _msvcrt_rand(state)
    expected_size = float(r_size % 10 + 0x1E)
    expected_health = expected_size * 1.1428572 + 20.0

    state, r_speed = _msvcrt_rand(state)
    expected_speed = float(r_speed % 0x12) * 0.1 + 1.1
    expected_reward = expected_size + expected_size + 50.0

    state, r_tint = _msvcrt_rand(state)
    expected_tint_g = float(r_tint % 0x14) * 0.01 + 0.8

    state, r_contact = _msvcrt_rand(state)
    expected_contact = float(r_contact % 10) + 4.0

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.SPIDER_SP2
    assert c.size == expected_size
    assert c.health == expected_health
    assert c.max_health == expected_health
    assert math.isclose(c.move_speed or 0.0, expected_speed, abs_tol=1e-9)
    assert c.reward_value == expected_reward
    assert c.contact_damage == expected_contact
    assert (c.tint_r, c.tint_g, c.tint_b, c.tint_a) == (0.8, expected_tint_g, 0.8, 1.0)
    assert c.heading == expected_heading

    assert rng.state == _step_msvcrt(seed, 7)


def test_spawn_plan_template_38_is_randomized_and_has_ai7_timer_flag() -> None:
    seed = 0xBEEF
    rng = Crand(seed)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x38, (100.0, 200.0), -100.0, rng, env)

    state = seed
    state, _ = _msvcrt_rand(state)  # alloc phase_seed
    state, r_heading = _msvcrt_rand(state)  # final heading
    expected_heading = float(r_heading % 0x274) * 0.01
    state, _ = _msvcrt_rand(state)  # base init random heading (overwritten)
    state, r_size = _msvcrt_rand(state)
    expected_size = float((r_size & 3) + 0x29)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.SPIDER_SP1
    assert c.flags == CreatureFlags.AI7_LINK_TIMER
    assert c.ai_timer == 0
    assert c.size == expected_size
    assert c.health == 50.0
    assert c.max_health == 50.0
    assert c.move_speed == 4.8
    assert c.reward_value == 433.0
    assert c.contact_damage == 10.0
    assert (c.tint_r, c.tint_g, c.tint_b, c.tint_a) == (1.0, 0.75, 0.1, 1.0)
    assert c.heading == expected_heading

    assert rng.state == _step_msvcrt(seed, 4)


def test_spawn_plan_template_41_is_randomized() -> None:
    seed = 0xBEEF
    rng = Crand(seed)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x41, (100.0, 200.0), -100.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    state = seed
    state, _ = _msvcrt_rand(state)  # alloc phase_seed
    state, r_heading = _msvcrt_rand(state)  # final heading
    expected_heading = float(r_heading % 0x274) * 0.01
    state, _ = _msvcrt_rand(state)  # base init random heading (overwritten)

    state, r_size = _msvcrt_rand(state)
    expected_size = float(r_size % 0x1E + 0x28)
    expected_health = expected_size * 1.1428572 + 10.0
    expected_speed = expected_size * 0.0025 + 0.9
    expected_reward = expected_size + expected_size + 50.0

    state, r_tint = _msvcrt_rand(state)
    expected_tint = float(r_tint % 0x28) * 0.01 + 0.6

    state, r_contact = _msvcrt_rand(state)
    expected_contact = float(r_contact % 10) + 4.0

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ZOMBIE
    assert c.size == expected_size
    assert c.health == expected_health
    assert c.max_health == expected_health
    assert c.move_speed == expected_speed
    assert c.reward_value == expected_reward
    assert c.contact_damage == expected_contact
    assert (c.tint_r, c.tint_g, c.tint_b, c.tint_a) == (expected_tint, expected_tint, expected_tint, 1.0)
    assert c.heading == expected_heading

    assert rng.state == _step_msvcrt(seed, 6)


def test_spawn_plan_template_0e_spawns_ring_children_and_has_spawn_slot() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x0E, (100.0, 200.0), 0.0, rng, env)

    assert len(plan.creatures) == 25
    assert plan.primary == 24
    assert len(plan.spawn_slots) == 1

    parent = plan.creatures[0]
    assert parent.type_id == CreatureTypeId.ALIEN
    assert parent.flags == CreatureFlags.ANIM_PING_PONG
    assert parent.spawn_slot == 0
    assert parent.health == 50.0
    assert parent.max_health is None  # tail applies to the last ring child
    assert parent.move_speed == 2.8
    assert parent.reward_value == 5000.0
    assert parent.size == 32.0
    assert (parent.tint_r, parent.tint_g, parent.tint_b, parent.tint_a) == (0.9, 0.8, 0.4, 1.0)
    assert parent.contact_damage == 0.0

    slot = plan.spawn_slots[0]
    assert slot.timer == 1.5
    assert slot.count == 0
    assert slot.limit == 0x40
    assert slot.child_template_id == 0x1C
    assert math.isclose(slot.interval, 1.0499999523162842, abs_tol=1e-9)

    for i, child in enumerate(plan.creatures[1:], start=0):
        assert child.type_id == CreatureTypeId.ALIEN
        assert child.ai_mode == 3
        assert child.ai_link_parent == 0
        assert child.pos_x == 100.0
        assert child.pos_y == 200.0
        assert child.phase_seed == 0.0
        assert child.health == 40.0
        assert child.max_health == 40.0
        assert child.move_speed == 4.0
        assert child.size == 35.0
        assert child.contact_damage == 30.0
        assert (child.tint_r, child.tint_g, child.tint_b, child.tint_a) == (1.0, 0.3, 0.3, 1.0)

        angle = float(i) * 0.2617994
        assert math.isclose(child.target_offset_x or 0.0, math.cos(angle) * 100.0, abs_tol=1e-4)
        assert math.isclose(child.target_offset_y or 0.0, math.sin(angle) * 100.0, abs_tol=1e-4)

    # Rand consumption:
    # - base alloc: 1
    # - base init random heading: 1
    # - 24 child allocs: 24
    assert rng.state == _step_msvcrt(0xBEEF, 26)


def test_spawn_plan_template_11_spawns_chain_children_and_falls_into_unhandled_override() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x11, (100.0, 200.0), 0.0, rng, env)

    assert len(plan.creatures) == 5
    assert plan.primary == 4
    assert plan.spawn_slots == ()

    parent = plan.creatures[0]
    assert parent.type_id == CreatureTypeId.LIZARD
    assert parent.ai_mode == 1
    assert parent.health == 1500.0
    assert parent.max_health == 1500.0
    assert parent.move_speed == 2.1
    assert parent.reward_value == 1000.0
    assert parent.size == 69.0
    assert (parent.tint_r, parent.tint_g, parent.tint_b, parent.tint_a) == (0.99, 0.99, 0.21, 1.0)
    assert parent.contact_damage == 150.0
    assert parent.ai_link_parent == 4

    offset_xs = (-256.0, -192.0, -128.0, -64.0)
    for i, child in enumerate(plan.creatures[1:], start=0):
        assert child.ai_mode == 3
        assert child.ai_link_parent == i
        assert child.target_offset_x == offset_xs[i]
        assert child.target_offset_y == -256.0
        assert child.reward_value == 60.0
        assert child.move_speed == 2.4
        assert child.size == 50.0
        assert child.contact_damage == 14.0
        assert (child.tint_r, child.tint_g, child.tint_b, child.tint_a) == (0.6, 0.6, 0.31, 1.0)

        angle = float(2 + 2 * i) * 0.3926991
        assert math.isclose(child.pos_x, 100.0 + math.cos(angle) * 256.0, abs_tol=1e-4)
        assert math.isclose(child.pos_y, 200.0 + math.sin(angle) * 256.0, abs_tol=1e-4)

    # The original falls into the "Unhandled creatureType.\n" block after the loop, which overwrites
    # the return creature (last child).
    assert plan.creatures[4].type_id == CreatureTypeId.ALIEN
    assert plan.creatures[4].health == 20.0
    assert plan.creatures[4].max_health == 20.0

    # Rand consumption:
    # - base alloc: 1
    # - base init random heading: 1
    # - 4 child allocs: 4
    assert rng.state == _step_msvcrt(0xBEEF, 6)
