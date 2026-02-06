from __future__ import annotations

import math

import pytest

from crimson.bonuses import BonusId
from grim.rand import Crand
from crimson.creatures.spawn import (
    CreatureFlags,
    CreatureTypeId,
    SPAWN_TEMPLATES,
    SpawnId,
    SpawnEnv,
    build_spawn_plan,
)


def _step_msvcrt(state: int, n: int) -> int:
    for _ in range(n):
        state = (state * 0x343FD + 0x269EC3) & 0xFFFFFFFF
    return state


def _msvcrt_rand(state: int) -> tuple[int, int]:
    """Return (new_state, rand_output) for MSVCRT rand()."""
    state = (state * 0x343FD + 0x269EC3) & 0xFFFFFFFF
    return state, (state >> 16) & 0x7FFF


def test_spawn_plan_effects_emit_when_demo_mode_disabled() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=False,
        hardcore=False,
        difficulty_level=0,
    )

    plan = build_spawn_plan(SpawnId.ALIEN_CONST_GREEN_24, (100.0, 200.0), 0.0, rng, env)

    assert len(plan.effects) == 1
    effect = plan.effects[0]
    assert effect.pos.x == 100.0
    assert effect.pos.y == 200.0
    assert effect.count == 8

    assert rng.state == _step_msvcrt(0xBEEF, 2)


def test_spawn_plan_effects_suppressed_in_demo_mode() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,
        hardcore=False,
        difficulty_level=0,
    )

    plan = build_spawn_plan(SpawnId.ALIEN_CONST_GREEN_24, (100.0, 200.0), 0.0, rng, env)

    assert plan.effects == ()
    assert rng.state == _step_msvcrt(0xBEEF, 2)


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
    assert c.tint == (0.6, 0.6, 1.0, 0.8)
    assert c.heading == 0.0

    slot = plan.spawn_slots[0]
    assert slot.owner_creature == 0
    assert slot.timer == 1.0
    assert slot.count == 0
    assert slot.limit == 0x32C
    assert slot.child_template_id == 0x41
    assert slot.interval == pytest.approx(0.9, abs=1e-9)

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
    assert c.tint == (0.8, 0.7, 0.4, 1.0)
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
    expected_health = expected_size * (8.0 / 7.0) + 20.0
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
    assert c.tint == (0.6, 0.6, expected_tint_b, 1.0)
    assert (c.move_speed or 0.0) == pytest.approx(expected_speed_pre_tail * 1.2, abs=1e-9)
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
    expected_health = expected_size * (8.0 / 7.0) + 20.0
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
    assert c.tint == (0.67, 0.67, 1.0, 1.0)
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
    expected_health = expected_size * (8.0 / 7.0) + 20.0
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
    assert c.tint == (0.6, 0.6, expected_tint_b, 1.0)
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
    expected_health = expected_size * (8.0 / 7.0) + 20.0
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
    assert c.tint == (0.6, 0.6, expected_tint_b, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(seed, 6)


def test_spawn_plan_template_3c_sets_ranged_projectile_type() -> None:
    rng = Crand(0)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,
        hardcore=False,
        difficulty_level=0,
    )

    plan = build_spawn_plan(SpawnId.SPIDER_SP1_CONST_RANGED_VARIANT_3C, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.SPIDER_SP1
    assert c.flags & CreatureFlags.RANGED_ATTACK_VARIANT
    assert c.ai_mode == 2
    assert c.ranged_projectile_type == 26


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
    assert c.tint == (1.0, 1.0, 1.0, 1.0)
    assert c.contact_damage == 0.0

    slot = plan.spawn_slots[0]
    assert slot.timer == 1.0
    assert slot.limit == 100
    assert slot.child_template_id == 0x1D
    # 2.2 + 0.2 tail bump.
    assert slot.interval == pytest.approx(2.4, abs=1e-9)

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
    assert c.tint == (1.0, 1.0, 1.0, 1.0)
    assert c.contact_damage == 0.0

    slot = plan.spawn_slots[0]
    assert slot.timer == 1.0
    assert slot.limit == 100
    assert slot.child_template_id == 0x1D
    # 2.8 + 0.2 tail bump.
    assert slot.interval == 3.0

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
    assert c.tint == (1.0, 1.0, 1.0, 1.0)
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
    assert c.tint == (0.8, 0.7, 0.4, 1.0)
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


def test_spawn_plan_template_0a_scales_with_difficulty() -> None:
    rng = Crand(0)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=2,
    )
    plan = build_spawn_plan(0x0A, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert len(plan.spawn_slots) == 1

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.flags == CreatureFlags.ANIM_PING_PONG
    assert c.spawn_slot == 0
    assert c.health == pytest.approx(1000.0 * 0.9, abs=1e-9)
    assert c.max_health == 1000.0
    assert c.move_speed == pytest.approx(1.5 * 0.9, abs=1e-9)
    assert c.reward_value == pytest.approx(3000.0 * 0.85, abs=1e-9)
    assert c.size == 55.0
    assert c.tint == (0.8, 0.7, 0.4, 1.0)
    assert c.contact_damage == 0.0

    slot = plan.spawn_slots[0]
    assert slot.interval == pytest.approx(5.0 + 0.2 + 0.7, abs=1e-9)

    assert rng.state == _step_msvcrt(0, 2)


def test_spawn_plan_template_0a_hardcore_buffs_and_shortens_interval() -> None:
    rng = Crand(0)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=True,
        difficulty_level=3,
    )
    plan = build_spawn_plan(0x0A, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert len(plan.spawn_slots) == 1

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.flags == CreatureFlags.ANIM_PING_PONG
    assert c.spawn_slot == 0
    assert c.health == pytest.approx(1000.0 * 1.2, abs=1e-9)
    assert c.max_health == 1000.0
    assert c.move_speed == pytest.approx(1.5 * 1.05, abs=1e-9)
    assert c.reward_value == 3000.0
    assert c.size == 55.0
    assert c.tint == (0.8, 0.7, 0.4, 1.0)
    assert c.contact_damage == 0.0

    slot = plan.spawn_slots[0]
    assert slot.interval == pytest.approx(5.0 - 0.2, abs=1e-9)

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
    assert c.tint == (0.9, 0.1, 0.1, 1.0)
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
    assert c.tint == (0.9, 0.8, 0.4, 1.0)
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
    assert c.tint == (0.9, 0.8, 0.4, 1.0)
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
    assert c.move_speed == 2.9
    assert c.reward_value == 60.0
    assert c.size == 50.0
    assert c.contact_damage == 35.0
    assert c.tint == (
        0.665,
        0.385,
        0.259,
        0.56,
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
    assert c.tint == (0.9, 0.8, 0.4, 1.0)
    assert c.contact_damage == 0.0

    slot = plan.spawn_slots[0]
    assert slot.interval == 2.5
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
    assert parent.tint == (0.65, 0.85, 0.97, 1.0)

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
        assert child.tint == (0.32, 0.588, 0.426, 1.0)

        angle = float(i) * (math.pi / 4.0)
        assert (child.target_offset_x or 0.0) == pytest.approx(math.cos(angle) * 100.0, abs=1e-4)
        assert (child.target_offset_y or 0.0) == pytest.approx(math.sin(angle) * 100.0, abs=1e-4)

    # Rand consumption:
    # - base alloc: 1
    # - base init random heading: 1
    # - 8 child allocs: 8
    assert rng.state == _step_msvcrt(0xBEEF, 10)


def test_spawn_plan_template_13_spawns_ring_children_and_links_parent() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x13, (100.0, 200.0), 0.0, rng, env)

    assert len(plan.creatures) == 11
    assert plan.primary == 10
    assert plan.spawn_slots == ()

    parent = plan.creatures[0]
    assert parent.type_id == CreatureTypeId.ALIEN
    assert parent.ai_mode == 6
    assert parent.ai_link_parent == 10
    assert parent.pos.x == 356.0
    assert parent.pos.y == 200.0
    assert parent.health == 200.0
    assert parent.max_health == 200.0
    assert parent.move_speed == 2.0
    assert parent.reward_value == 600.0
    assert parent.size == 40.0
    assert parent.contact_damage == 20.0
    assert parent.tint == (0.6, 0.8, 0.91, 1.0)

    for i, child in enumerate(plan.creatures[1:], start=0):
        assert child.type_id == CreatureTypeId.ALIEN
        assert child.ai_mode == 6
        assert child.ai_link_parent == i
        assert child.orbit_angle == math.pi
        assert child.orbit_radius == 10.0

        expected_health = 20.0 if i == 9 else 60.0
        assert child.health == expected_health
        assert child.max_health == expected_health
        assert child.move_speed == 2.0
        assert child.reward_value == 60.0
        assert child.size == 50.0
        assert child.contact_damage == 4.0
        assert child.tint == (0.4, 0.7, 0.11, 1.0)

        angle = float(2 + 2 * i) * math.radians(20.0)
        assert child.pos.x == pytest.approx(100.0 + math.cos(angle) * 256.0, abs=1e-4)
        assert child.pos.y == pytest.approx(200.0 + math.sin(angle) * 256.0, abs=1e-4)

    # Rand consumption:
    # - base alloc: 1
    # - base init random heading: 1
    # - 10 child allocs: 10
    assert rng.state == _step_msvcrt(0xBEEF, 12)


def test_spawn_plan_template_14_spawns_grid_children() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x14, (100.0, 200.0), 0.0, rng, env)

    assert len(plan.creatures) == 82
    assert plan.primary == 81
    assert plan.spawn_slots == ()

    parent = plan.creatures[0]
    assert parent.type_id == CreatureTypeId.ALIEN
    assert parent.ai_mode == 2
    assert parent.health == 1500.0
    assert parent.max_health == 1500.0
    assert parent.move_speed == 2.0
    assert parent.reward_value == 600.0
    assert parent.size == 50.0
    assert parent.contact_damage == 40.0
    assert parent.tint == (0.7, 0.8, 0.31, 1.0)

    for idx, child in enumerate(plan.creatures[1:], start=0):
        x_offset = float(-64 * (idx // 9))
        y_offset = float(0x80 + 0x10 * (idx % 9))
        assert child.type_id == CreatureTypeId.ALIEN
        assert child.ai_mode == 5
        assert child.ai_link_parent == 0
        assert child.target_offset_x == x_offset
        assert child.target_offset_y == y_offset
        assert child.pos.x == 100.0 + x_offset
        assert child.pos.y == 200.0 + y_offset

        expected_health = 20.0 if idx == 80 else 40.0
        assert child.health == expected_health
        assert child.max_health == expected_health
        assert child.move_speed == 2.0
        assert child.reward_value == 60.0
        assert child.size == 50.0
        assert child.contact_damage == 4.0
        assert child.tint == (0.4, 0.7, 0.11, 1.0)

    # Rand consumption:
    # - base alloc: 1
    # - base init random heading: 1
    # - 81 child allocs: 81
    assert rng.state == _step_msvcrt(0xBEEF, 83)


def test_spawn_plan_template_15_spawns_grid_children() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x15, (100.0, 200.0), 0.0, rng, env)

    assert len(plan.creatures) == 82
    assert plan.primary == 81
    assert plan.spawn_slots == ()

    parent = plan.creatures[0]
    assert parent.type_id == CreatureTypeId.ALIEN
    assert parent.ai_mode == 2
    assert parent.health == 1500.0
    assert parent.max_health == 1500.0
    assert parent.move_speed == 2.0
    assert parent.reward_value == 600.0
    assert parent.size == 60.0
    assert parent.contact_damage == 40.0
    assert parent.tint == (1.0, 1.0, 1.0, 1.0)

    for idx, child in enumerate(plan.creatures[1:], start=0):
        x_offset = float(-64 * (idx // 9))
        y_offset = float(0x80 + 0x10 * (idx % 9))
        assert child.type_id == CreatureTypeId.ALIEN
        assert child.ai_mode == 4
        assert child.ai_link_parent == 0
        assert child.target_offset_x == x_offset
        assert child.target_offset_y == y_offset
        assert child.pos.x == 100.0 + x_offset
        assert child.pos.y == 200.0 + y_offset

        expected_health = 20.0 if idx == 80 else 40.0
        assert child.health == expected_health
        assert child.max_health == expected_health
        assert child.move_speed == 2.0
        assert child.reward_value == 60.0
        assert child.size == 50.0
        assert child.contact_damage == 4.0
        assert child.tint == (0.4, 0.7, 0.11, 1.0)

    # Rand consumption:
    # - base alloc: 1
    # - base init random heading: 1
    # - 81 child allocs: 81
    assert rng.state == _step_msvcrt(0xBEEF, 83)


def test_spawn_plan_template_16_spawns_grid_children() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x16, (100.0, 200.0), 0.0, rng, env)

    assert len(plan.creatures) == 82
    assert plan.primary == 81
    assert plan.spawn_slots == ()

    parent = plan.creatures[0]
    assert parent.type_id == CreatureTypeId.LIZARD
    assert parent.ai_mode == 2
    assert parent.health == 1500.0
    assert parent.max_health == 1500.0
    assert parent.move_speed == 2.0
    assert parent.reward_value == 600.0
    assert parent.size == 64.0
    assert parent.contact_damage == 40.0
    assert parent.tint == (1.0, 1.0, 1.0, 1.0)

    for idx, child in enumerate(plan.creatures[1:], start=0):
        x_offset = float(-64 * (idx // 9))
        y_offset = float(0x80 + 0x10 * (idx % 9))
        expected_type = CreatureTypeId.ALIEN if idx == 80 else CreatureTypeId.LIZARD
        assert child.type_id == expected_type
        assert child.ai_mode == 4
        assert child.ai_link_parent == 0
        assert child.target_offset_x == x_offset
        assert child.target_offset_y == y_offset
        assert child.pos.x == 100.0 + x_offset
        assert child.pos.y == 200.0 + y_offset

        expected_health = 20.0 if idx == 80 else 40.0
        assert child.health == expected_health
        assert child.max_health == expected_health
        assert child.move_speed == 2.0
        assert child.reward_value == 60.0
        assert child.size == 60.0
        assert child.contact_damage == 4.0
        assert child.tint == (0.4, 0.7, 0.11, 1.0)

    # Rand consumption:
    # - base alloc: 1
    # - base init random heading: 1
    # - 81 child allocs: 81
    assert rng.state == _step_msvcrt(0xBEEF, 83)


def test_spawn_plan_template_17_spawns_grid_children() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x17, (100.0, 200.0), 0.0, rng, env)

    assert len(plan.creatures) == 82
    assert plan.primary == 81
    assert plan.spawn_slots == ()

    parent = plan.creatures[0]
    assert parent.type_id == CreatureTypeId.SPIDER_SP1
    assert parent.ai_mode == 2
    assert parent.health == 1500.0
    assert parent.max_health == 1500.0
    assert parent.move_speed == 2.0
    assert parent.reward_value == 600.0
    assert parent.size == 60.0
    assert parent.contact_damage == 40.0
    assert parent.tint == (1.0, 1.0, 1.0, 1.0)

    for idx, child in enumerate(plan.creatures[1:], start=0):
        x_offset = float(-64 * (idx // 9))
        y_offset = float(0x80 + 0x10 * (idx % 9))
        expected_type = CreatureTypeId.ALIEN if idx == 80 else CreatureTypeId.SPIDER_SP1
        assert child.type_id == expected_type
        assert child.ai_mode == 4
        assert child.ai_link_parent == 0
        assert child.target_offset_x == x_offset
        assert child.target_offset_y == y_offset
        assert child.pos.x == 100.0 + x_offset
        assert child.pos.y == 200.0 + y_offset

        expected_health = 20.0 if idx == 80 else 40.0
        assert child.health == expected_health
        assert child.max_health == expected_health
        assert child.move_speed == 2.0
        assert child.reward_value == 60.0
        assert child.size == 50.0
        assert child.contact_damage == 4.0
        assert child.tint == (0.4, 0.7, 0.11, 1.0)

    # Rand consumption:
    # - base alloc: 1
    # - base init random heading: 1
    # - 81 child allocs: 81
    assert rng.state == _step_msvcrt(0xBEEF, 83)


def test_spawn_plan_template_18_spawns_grid_children() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x18, (100.0, 200.0), 0.0, rng, env)

    assert len(plan.creatures) == 82
    assert plan.primary == 81
    assert plan.spawn_slots == ()

    parent = plan.creatures[0]
    assert parent.type_id == CreatureTypeId.ALIEN
    assert parent.ai_mode == 2
    assert parent.health == 500.0
    assert parent.max_health == 500.0
    assert parent.move_speed == 2.0
    assert parent.reward_value == 600.0
    assert parent.size == 40.0
    assert parent.contact_damage == 40.0
    assert parent.tint == (0.7, 0.8, 0.31, 1.0)

    for idx, child in enumerate(plan.creatures[1:], start=0):
        x_offset = float(-64 * (idx // 9))
        y_offset = float(0x80 + 0x10 * (idx % 9))
        assert child.type_id == CreatureTypeId.ALIEN
        assert child.ai_mode == 3
        assert child.ai_link_parent == 0
        assert child.target_offset_x == x_offset
        assert child.target_offset_y == y_offset
        assert child.pos.x == 100.0 + x_offset
        assert child.pos.y == 200.0 + y_offset

        expected_health = 260.0
        assert child.health == expected_health
        assert child.max_health == expected_health
        assert child.move_speed == 3.8
        assert child.reward_value == 60.0
        assert child.size == 50.0
        assert child.contact_damage == 35.0
        assert child.tint == (0.7125, 0.4125, 0.2775, 0.6)

    # Rand consumption:
    # - base alloc: 1
    # - base init random heading: 1
    # - 81 child allocs: 81
    assert rng.state == _step_msvcrt(0xBEEF, 83)


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
    assert parent.tint == (0.95, 0.55, 0.37, 1.0)

    for i, child in enumerate(plan.creatures[1:], start=0):
        assert child.type_id == CreatureTypeId.ALIEN
        assert child.ai_mode == 5
        assert child.ai_link_parent == 0
        expected_health = 20.0 if i == 4 else 220.0
        assert child.health == expected_health
        assert child.max_health == expected_health
        assert child.move_speed == 3.8
        assert child.size == 50.0
        assert child.tint == (0.7125, 0.4125, 0.2775, 0.6)

        angle = float(i) * (math.tau / 5.0)
        assert (child.target_offset_x or 0.0) == pytest.approx(math.cos(angle) * 110.0, abs=1e-4)
        assert (child.target_offset_y or 0.0) == pytest.approx(math.sin(angle) * 110.0, abs=1e-4)
        assert child.pos.x == pytest.approx(100.0 + (child.target_offset_x or 0.0), abs=1e-4)
        assert child.pos.y == pytest.approx(200.0 + (child.target_offset_y or 0.0), abs=1e-4)

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
    assert c.tint == (expected_tint, expected_tint, 1.0, 1.0)
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
    assert (c.move_speed or 0.0) == pytest.approx(2.4 * 1.2, abs=1e-9)
    assert c.reward_value == 125.0
    assert c.contact_damage == 5.0
    assert c.tint == (expected_tint, expected_tint, 1.0, 1.0)
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
    assert c.tint == (expected_tint, expected_tint, 1.0, 1.0)
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
    expected_health = expected_size * (8.0 / 7.0) + 10.0

    state, r_speed = _msvcrt_rand(state)
    expected_speed = float(r_speed % 15) * 0.1 + 1.1

    state, r_reward = _msvcrt_rand(state)
    expected_reward = float(r_reward % 100 + 50)

    state, r_tint_r = _msvcrt_rand(state)
    expected_tint_r = float(r_tint_r % 50) * 0.001 + 0.6

    state, r_tint_g = _msvcrt_rand(state)
    expected_tint_g = float(r_tint_g % 50) * 0.01 + 0.5

    state, r_tint_b = _msvcrt_rand(state)
    expected_tint_b = float(r_tint_b % 50) * 0.001 + 0.6

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
    assert c.tint == (expected_tint_r, expected_tint_g, expected_tint_b, 1.0)
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
    expected_health = expected_size * (16.0 / 7.0) + 10.0

    state, r_speed = _msvcrt_rand(state)
    expected_speed = float(r_speed % 17) * 0.1 + 1.5

    state, r_reward = _msvcrt_rand(state)
    expected_reward = float(r_reward % 200 + 50)

    state, r_tint_r = _msvcrt_rand(state)
    expected_tint_r = float(r_tint_r % 50) * 0.001 + 0.6

    state, r_tint_g = _msvcrt_rand(state)
    expected_tint_g = float(r_tint_g % 50) * 0.001 + 0.6

    state, r_tint_b = _msvcrt_rand(state)
    expected_tint_b = float(r_tint_b % 50) * 0.01 + 0.5

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
    assert c.tint == (expected_tint_r, expected_tint_g, expected_tint_b, 1.0)
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
    expected_health = expected_size * (26.0 / 7.0) + 30.0

    state, r_speed = _msvcrt_rand(state)
    expected_speed = float(r_speed % 21) * 0.1 + 1.6

    state, r_reward = _msvcrt_rand(state)
    expected_reward = float(r_reward % 200 + 80)

    state, r_tint_r = _msvcrt_rand(state)
    expected_tint_r = float(r_tint_r % 50) * 0.01 + 0.5

    state, r_tint_g = _msvcrt_rand(state)
    expected_tint_g = float(r_tint_g % 50) * 0.001 + 0.6

    state, r_tint_b = _msvcrt_rand(state)
    expected_tint_b = float(r_tint_b % 50) * 0.001 + 0.6

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
    assert c.tint == (expected_tint_r, expected_tint_g, expected_tint_b, 1.0)
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
    expected_health = expected_size * (8.0 / 7.0) + 20.0

    state, r_speed = _msvcrt_rand(state)
    expected_speed = float(r_speed % 18) * 0.1 + 1.1
    expected_reward = expected_size + expected_size + 50.0

    state, r_tint_g = _msvcrt_rand(state)
    expected_tint_g = float(r_tint_g % 40) * 0.01 + 0.6

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
    assert c.tint == (0.3, expected_tint_g, 0.3, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(seed, 6)


def test_spawn_plan_template_21_is_constant() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x21, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.health == 53.0
    assert c.max_health == 53.0
    assert c.move_speed == 1.7
    assert c.reward_value == 120.0
    assert c.size == 55.0
    assert c.contact_damage == 8.0
    assert c.tint == (0.7, 0.1, 0.51, 0.5)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(0xBEEF, 2)


def test_spawn_plan_template_21_scales_with_difficulty() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=2,
    )
    plan = build_spawn_plan(0x21, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.health == pytest.approx(53.0 * 0.9, abs=1e-9)
    assert c.max_health == 53.0
    assert c.move_speed == pytest.approx(1.7 * 0.9, abs=1e-9)
    assert c.reward_value == pytest.approx(120.0 * 0.85, abs=1e-9)
    assert c.size == 55.0
    assert c.contact_damage == pytest.approx(8.0 * 0.9, abs=1e-9)
    assert c.tint == (0.7, 0.1, 0.51, 0.5)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(0xBEEF, 2)


def test_spawn_plan_template_22_is_constant() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x22, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.health == 25.0
    assert c.max_health == 25.0
    assert c.move_speed == 1.7
    assert c.reward_value == 150.0
    assert c.size == 50.0
    assert c.contact_damage == 8.0
    assert c.tint == (0.1, 0.7, 0.51, 0.05)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(0xBEEF, 2)


def test_spawn_plan_template_23_is_constant() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x23, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.health == 5.0
    assert c.max_health == 5.0
    assert c.move_speed == 1.7
    assert c.reward_value == 180.0
    assert c.size == 45.0
    assert c.contact_damage == 8.0
    assert c.tint == (0.1, 0.7, 0.51, 0.04)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(0xBEEF, 2)


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
    assert c.tint == (0.1, 0.7, 0.11, 1.0)
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
    assert c.tint == (0.1, 0.8, 0.11, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(0xBEEF, 2)


def test_spawn_plan_template_26_is_constant() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x26, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.health == 50.0
    assert c.max_health == 50.0
    assert c.move_speed == 2.2
    assert c.reward_value == 125.0
    assert c.size == 45.0
    assert c.contact_damage == 10.0
    assert c.tint == (0.6, 0.8, 0.6, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(0xBEEF, 2)


def test_spawn_plan_template_27_is_constant() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x27, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.flags == CreatureFlags.BONUS_ON_DEATH
    assert c.bonus_id == BonusId.WEAPON
    assert c.bonus_duration_override == 5
    assert c.health == 50.0
    assert c.max_health == 50.0
    assert c.move_speed == 2.1
    assert c.reward_value == 125.0
    assert c.size == 45.0
    assert c.contact_damage == 10.0
    assert c.tint == (1.0, 0.8, 0.1, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(0xBEEF, 2)


def test_spawn_plan_template_28_is_constant() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x28, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.health == 50.0
    assert c.max_health == 50.0
    assert c.move_speed == 1.7
    assert c.reward_value == 150.0
    assert c.size == 55.0
    assert c.contact_damage == 8.0
    assert c.tint == (0.7, 0.1, 0.51, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(0xBEEF, 2)


def test_spawn_plan_template_29_is_constant() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x29, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.health == 800.0
    assert c.max_health == 800.0
    assert c.move_speed == 2.5
    assert c.reward_value == 450.0
    assert c.size == 70.0
    assert c.contact_damage == 20.0
    assert c.tint == (0.8, 0.8, 0.8, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(0xBEEF, 2)


def test_spawn_plan_template_2a_is_constant() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x2A, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.health == 50.0
    assert c.max_health == 50.0
    assert c.move_speed == 3.1
    assert c.reward_value == 300.0
    assert c.size == 60.0
    assert c.contact_damage == 8.0
    assert c.tint == (0.3, 0.3, 0.3, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(0xBEEF, 2)


def test_spawn_plan_template_2b_is_constant() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x2B, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.health == 30.0
    assert c.max_health == 30.0
    assert c.move_speed == 3.6
    assert c.reward_value == 450.0
    assert c.size == 35.0
    assert c.contact_damage == 20.0
    assert c.tint == (1.0, 0.3, 0.3, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(0xBEEF, 2)


def test_spawn_plan_template_2c_is_constant() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x2C, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.health == 3800.0
    assert c.max_health == 3800.0
    assert c.move_speed == 2.0
    assert c.reward_value == 1500.0
    assert c.size == 80.0
    assert c.contact_damage == 40.0
    assert c.tint == (0.85, 0.2, 0.2, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(0xBEEF, 2)


def test_spawn_plan_template_2d_is_constant() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x2D, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.ai_mode == 2
    assert c.health == 45.0
    assert c.max_health == 45.0
    assert c.move_speed == 3.1
    assert c.reward_value == 200.0
    assert c.size == 38.0
    assert c.contact_damage == 3.0
    assert c.tint == (0.0, 0.9, 0.8, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(0xBEEF, 2)


def test_spawn_plan_template_2e_is_randomized() -> None:
    seed = 0xBEEF
    rng = Crand(seed)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x2E, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    state = seed
    state, _ = _msvcrt_rand(state)  # alloc phase_seed
    state, _ = _msvcrt_rand(state)  # base init random heading (overwritten)

    state, r_size = _msvcrt_rand(state)
    expected_size = float(r_size % 0x1E + 0x28)
    expected_health = expected_size * (8.0 / 7.0) + 20.0

    state, r_speed = _msvcrt_rand(state)
    expected_speed = float(r_speed % 0x12) * 0.1 + 1.1
    expected_reward = expected_size + expected_size + 50.0

    state, r_tint_r = _msvcrt_rand(state)
    expected_tint_r = float(r_tint_r % 0x28) * 0.01 + 0.6

    state, r_tint_g = _msvcrt_rand(state)
    expected_tint_g = float(r_tint_g % 0x28) * 0.01 + 0.6

    state, r_tint_b = _msvcrt_rand(state)
    expected_tint_b = float(r_tint_b % 0x28) * 0.01 + 0.6

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
    assert c.tint == (expected_tint_r, expected_tint_g, expected_tint_b, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(seed, 8)


def test_spawn_plan_template_2f_is_constant() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x2F, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.LIZARD
    assert c.health == 20.0
    assert c.max_health == 20.0
    assert c.move_speed == 2.5
    assert c.reward_value == 150.0
    assert c.size == 45.0
    assert c.contact_damage == 4.0
    assert c.tint == (0.8, 0.8, 0.8, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(0xBEEF, 2)


def test_spawn_plan_template_30_is_constant() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x30, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.LIZARD
    assert c.health == 1000.0
    assert c.max_health == 1000.0
    assert c.move_speed == 2.0
    assert c.reward_value == 400.0
    assert c.size == 65.0
    assert c.contact_damage == 10.0
    assert c.tint == (0.9, 0.8, 0.1, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(0xBEEF, 2)


def test_spawn_plan_template_31_is_randomized() -> None:
    seed = 0xBEEF
    rng = Crand(seed)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x31, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    state = seed
    state, _ = _msvcrt_rand(state)  # alloc phase_seed
    state, _ = _msvcrt_rand(state)  # base init random heading (overwritten)

    state, r_size = _msvcrt_rand(state)
    expected_size = float(r_size % 0x1E + 0x28)
    expected_health = expected_size * (8.0 / 7.0) + 10.0

    state, r_speed = _msvcrt_rand(state)
    expected_speed = float(r_speed % 0x12) * 0.1 + 1.1
    expected_reward = expected_size + expected_size + 50.0

    state, r_tint = _msvcrt_rand(state)
    expected_tint = float(r_tint % 0x1E) * 0.01 + 0.6

    expected_contact = expected_size * 0.14 + 4.0

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.LIZARD
    assert c.size == expected_size
    assert c.health == expected_health
    assert c.max_health == expected_health
    assert c.move_speed == expected_speed
    assert c.reward_value == expected_reward
    assert c.contact_damage == expected_contact
    assert c.tint == (expected_tint, expected_tint, 0.38, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(seed, 5)


def test_spawn_plan_template_32_is_randomized_and_tail_enables_ai7_timer() -> None:
    seed = 0xBEEF
    rng = Crand(seed)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x32, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    state = seed
    state, _ = _msvcrt_rand(state)  # alloc phase_seed
    state, _ = _msvcrt_rand(state)  # base init random heading (overwritten)

    state, r_size = _msvcrt_rand(state)
    expected_size = float(r_size % 0x19 + 0x28)
    expected_health = expected_size + 10.0

    state, r_speed = _msvcrt_rand(state)
    expected_speed_pre_tail = float(r_speed % 0x11) * 0.1 + 1.1
    expected_reward = expected_size + expected_size + 50.0

    state, r_tint = _msvcrt_rand(state)
    expected_tint = float(r_tint % 0x28) * 0.01 + 0.6

    expected_contact = expected_size * 0.14 + 4.0

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.SPIDER_SP1
    assert c.flags == CreatureFlags.AI7_LINK_TIMER
    assert c.ai_timer == 0
    assert c.size == expected_size
    assert c.health == expected_health
    assert c.max_health == expected_health
    assert (c.move_speed or 0.0) == pytest.approx(expected_speed_pre_tail * 1.2, abs=1e-9)
    assert c.reward_value == expected_reward
    assert c.contact_damage == expected_contact
    assert c.tint == (expected_tint, expected_tint, expected_tint, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(seed, 5)


def test_spawn_plan_template_33_is_randomized_and_tail_enables_ai7_timer() -> None:
    seed = 0xBEEF
    rng = Crand(seed)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x33, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    state = seed
    state, _ = _msvcrt_rand(state)  # alloc phase_seed
    state, _ = _msvcrt_rand(state)  # base init random heading (overwritten)

    state, r_size = _msvcrt_rand(state)
    expected_size = float(r_size % 0xF + 0x2D)
    expected_health = expected_size * (8.0 / 7.0) + 20.0

    state, r_speed = _msvcrt_rand(state)
    expected_speed_pre_tail = float(r_speed % 0x12) * 0.1 + 1.1
    expected_reward = expected_size + expected_size + 50.0

    state, r_tint = _msvcrt_rand(state)
    expected_tint_r = float(r_tint % 0x28) * 0.01 + 0.6

    state, r_contact = _msvcrt_rand(state)
    expected_contact = float(r_contact % 10) + 4.0

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.SPIDER_SP1
    assert c.flags == CreatureFlags.AI7_LINK_TIMER
    assert c.ai_timer == 0
    assert c.size == expected_size
    assert c.health == expected_health
    assert c.max_health == expected_health
    assert (c.move_speed or 0.0) == pytest.approx(expected_speed_pre_tail * 1.2, abs=1e-9)
    assert c.reward_value == expected_reward
    assert c.contact_damage == expected_contact
    assert c.tint == (expected_tint_r, 0.5, 0.5, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(seed, 6)


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
    expected_health = expected_size * (8.0 / 7.0) + 20.0

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
    assert c.tint == (0.5, expected_tint_g, 0.5, 1.0)
    assert (c.move_speed or 0.0) == pytest.approx(expected_speed_pre_tail * 1.2, abs=1e-9)
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
    expected_health = expected_size * (8.0 / 7.0) + 20.0

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
    assert (c.move_speed or 0.0) == pytest.approx(expected_speed, abs=1e-9)
    assert c.reward_value == expected_reward
    assert c.contact_damage == expected_contact
    assert c.tint == (0.8, expected_tint_g, 0.8, 1.0)
    assert c.heading == expected_heading

    assert rng.state == _step_msvcrt(seed, 7)


def test_spawn_plan_template_36_is_randomized_tint() -> None:
    seed = 0xBEEF
    rng = Crand(seed)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x36, (100.0, 200.0), 0.0, rng, env)

    state = seed
    state, _ = _msvcrt_rand(state)  # alloc phase_seed
    state, _ = _msvcrt_rand(state)  # base init random heading
    state, r_tint_g = _msvcrt_rand(state)
    expected_tint_g = float(r_tint_g % 5) * 0.01 + 0.65

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ALIEN
    assert c.ai_mode == 7
    assert c.orbit_radius == 1.5
    assert c.size == 50.0
    assert c.health == 10.0
    assert c.max_health == 10.0
    assert c.move_speed == 1.8
    assert c.reward_value == 150.0
    assert c.contact_damage == 40.0
    assert c.tint == (0.65, expected_tint_g, 0.95, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(seed, 3)


def test_spawn_plan_template_37_is_randomized() -> None:
    seed = 0xBEEF
    rng = Crand(seed)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x37, (100.0, 200.0), 0.0, rng, env)

    state = seed
    state, _ = _msvcrt_rand(state)  # alloc phase_seed
    state, _ = _msvcrt_rand(state)  # base init random heading
    state, r_size = _msvcrt_rand(state)
    expected_size = float((r_size & 3) + 0x29)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.SPIDER_SP2
    assert c.flags == CreatureFlags.RANGED_ATTACK_VARIANT
    assert c.size == expected_size
    assert c.health == 50.0
    assert c.max_health == 50.0
    assert c.move_speed == 3.2
    assert c.reward_value == 433.0
    assert c.contact_damage == 10.0
    assert c.tint == (1.0, 0.75, 0.1, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(seed, 3)


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
    assert c.tint == (1.0, 0.75, 0.1, 1.0)
    assert c.heading == expected_heading

    assert rng.state == _step_msvcrt(seed, 4)


def test_spawn_plan_template_39_is_randomized_and_has_ai7_timer_flag() -> None:
    seed = 0xBEEF
    rng = Crand(seed)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x39, (100.0, 200.0), 0.0, rng, env)

    state = seed
    state, _ = _msvcrt_rand(state)  # alloc phase_seed
    state, _ = _msvcrt_rand(state)  # base init random heading
    state, r_size = _msvcrt_rand(state)
    expected_size = float(r_size % 4 + 26)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.SPIDER_SP1
    assert c.flags == CreatureFlags.AI7_LINK_TIMER
    assert c.ai_timer == 0
    assert c.size == expected_size
    assert c.health == 4.0
    assert c.max_health == 4.0
    assert c.move_speed == 4.8
    assert c.reward_value == 50.0
    assert c.contact_damage == 10.0
    assert c.tint == (0.8, 0.65, 0.1, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(seed, 3)


def test_spawn_plan_template_3a_is_constant_and_has_ranged_shock_flag() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x3A, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.SPIDER_SP1
    assert c.flags == CreatureFlags.RANGED_ATTACK_SHOCK
    assert c.orbit_angle == 0.9
    assert c.orbit_radius is None
    assert c.ranged_projectile_type == 9
    assert c.ai_timer is None
    assert c.health == 4500.0
    assert c.max_health == 4500.0
    assert c.move_speed == 2.0
    assert c.reward_value == 4500.0
    assert c.size == 64.0
    assert c.contact_damage == 50.0
    assert c.tint == (1.0, 1.0, 1.0, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(0xBEEF, 2)


def test_spawn_plan_template_3b_is_constant_and_tail_enables_ai7_timer() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x3B, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.SPIDER_SP1
    assert c.flags == CreatureFlags.AI7_LINK_TIMER
    assert c.ai_timer == 0
    assert c.health == 1200.0
    assert c.max_health == 1200.0
    assert (c.move_speed or 0.0) == pytest.approx(2.0 * 1.2, abs=1e-9)
    assert c.reward_value == 4000.0
    assert c.size == 70.0
    assert c.contact_damage == 20.0
    assert c.tint == (0.9, 0.0, 0.0, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(0xBEEF, 2)


def test_spawn_plan_template_3c_is_constant_and_tail_enables_ai7_timer() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x3C, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.SPIDER_SP1
    assert c.flags == (CreatureFlags.RANGED_ATTACK_VARIANT | CreatureFlags.AI7_LINK_TIMER)
    assert c.ai_timer == 0
    assert c.ai_mode == 2
    assert c.orbit_angle == 0.4
    assert c.orbit_radius is None
    assert c.ranged_projectile_type == 26
    assert c.health == 200.0
    assert c.max_health == 200.0
    assert (c.move_speed or 0.0) == pytest.approx(2.0 * 1.2, abs=1e-9)
    assert c.reward_value == 200.0
    assert c.size == 40.0
    assert c.contact_damage == 20.0
    assert c.tint == (0.9, 0.1, 0.1, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(0xBEEF, 2)


def test_spawn_plan_template_3d_is_randomized_and_tail_enables_ai7_timer() -> None:
    seed = 0xBEEF
    rng = Crand(seed)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x3D, (100.0, 200.0), 0.0, rng, env)

    state = seed
    state, _ = _msvcrt_rand(state)  # alloc phase_seed
    state, _ = _msvcrt_rand(state)  # base init random heading
    state, r_tint = _msvcrt_rand(state)
    expected_tint = float(r_tint % 20) * 0.01 + 0.8
    state, r_size = _msvcrt_rand(state)
    expected_size = float(r_size % 7 + 45)
    expected_contact = expected_size * 0.22

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.SPIDER_SP1
    assert c.flags == CreatureFlags.AI7_LINK_TIMER
    assert c.ai_timer == 0
    assert c.health == 70.0
    assert c.max_health == 70.0
    assert (c.move_speed or 0.0) == pytest.approx(2.6 * 1.2, abs=1e-9)
    assert c.reward_value == 120.0
    assert c.size == expected_size
    assert (c.contact_damage or 0.0) == pytest.approx(expected_contact, abs=1e-9)
    assert c.tint == (expected_tint, expected_tint, expected_tint, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(seed, 4)


def test_spawn_plan_template_3e_is_constant_and_tail_enables_ai7_timer() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x3E, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.SPIDER_SP1
    assert c.flags == CreatureFlags.AI7_LINK_TIMER
    assert c.ai_timer == 0
    assert c.health == 1000.0
    assert c.max_health == 1000.0
    assert (c.move_speed or 0.0) == pytest.approx(2.8 * 1.2, abs=1e-9)
    assert c.reward_value == 500.0
    assert c.size == 64.0
    assert c.contact_damage == 40.0
    assert c.tint == (1.0, 1.0, 1.0, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(0xBEEF, 2)


def test_spawn_plan_template_3f_is_constant_and_tail_enables_ai7_timer() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x3F, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.SPIDER_SP1
    assert c.flags == CreatureFlags.AI7_LINK_TIMER
    assert c.ai_timer == 0
    assert c.health == 200.0
    assert c.max_health == 200.0
    assert (c.move_speed or 0.0) == pytest.approx(2.3 * 1.2, abs=1e-9)
    assert c.reward_value == 210.0
    assert c.size == 35.0
    assert c.contact_damage == 20.0
    assert c.tint == (0.7, 0.4, 0.1, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(0xBEEF, 2)


def test_spawn_plan_template_40_is_constant_and_tail_enables_ai7_timer() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x40, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.SPIDER_SP1
    assert c.flags == CreatureFlags.AI7_LINK_TIMER
    assert c.ai_timer == 0
    assert c.health == 70.0
    assert c.max_health == 70.0
    assert (c.move_speed or 0.0) == pytest.approx(2.2 * 1.2, abs=1e-9)
    assert c.reward_value == 160.0
    assert c.size == 45.0
    assert c.contact_damage == 5.0
    assert c.tint == (0.5, 0.6, 0.9, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(0xBEEF, 2)


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
    expected_health = expected_size * (8.0 / 7.0) + 10.0
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
    assert c.tint == (expected_tint, expected_tint, expected_tint, 1.0)
    assert c.heading == expected_heading

    assert rng.state == _step_msvcrt(seed, 6)


def test_spawn_plan_template_42_is_constant() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x42, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ZOMBIE
    assert c.flags == CreatureFlags(0)
    assert c.health == 200.0
    assert c.max_health == 200.0
    assert c.move_speed == 1.7
    assert c.reward_value == 160.0
    assert c.size == 45.0
    assert c.contact_damage == 15.0
    assert c.tint == (0.9, 0.9, 0.9, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(0xBEEF, 2)


def test_spawn_plan_template_43_is_constant() -> None:
    rng = Crand(0xBEEF)
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=True,  # avoid effect noise
        hardcore=False,
        difficulty_level=0,
    )
    plan = build_spawn_plan(0x43, (100.0, 200.0), 0.0, rng, env)

    assert plan.primary == 0
    assert len(plan.creatures) == 1
    assert plan.spawn_slots == ()

    c = plan.creatures[0]
    assert c.type_id == CreatureTypeId.ZOMBIE
    assert c.flags == CreatureFlags(0)
    assert c.health == 2000.0
    assert c.max_health == 2000.0
    assert c.move_speed == 2.1
    assert c.reward_value == 460.0
    assert c.size == 70.0
    assert c.contact_damage == 15.0
    assert c.tint == (0.2, 0.6, 0.1, 1.0)
    assert c.heading == 0.0

    assert rng.state == _step_msvcrt(0xBEEF, 2)


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
    assert parent.tint == (0.9, 0.8, 0.4, 1.0)
    assert parent.contact_damage == 0.0

    slot = plan.spawn_slots[0]
    assert slot.timer == 1.5
    assert slot.count == 0
    assert slot.limit == 0x40
    assert slot.child_template_id == 0x1C
    assert slot.interval == 1.05

    state = 0xBEEF
    state, _ = _msvcrt_rand(state)  # base alloc phase_seed
    state, _ = _msvcrt_rand(state)  # base init random heading

    for i, child in enumerate(plan.creatures[1:], start=0):
        state, r_phase_seed = _msvcrt_rand(state)
        assert child.type_id == CreatureTypeId.ALIEN
        assert child.ai_mode == 3
        assert child.ai_link_parent == 0
        assert child.pos.x == 100.0
        assert child.pos.y == 200.0
        assert child.phase_seed == float(r_phase_seed & 0x17F)
        assert child.health == 40.0
        assert child.max_health == 40.0
        assert child.move_speed == 4.0
        assert child.size == 35.0
        assert child.contact_damage == 30.0
        assert child.tint == (1.0, 0.3, 0.3, 1.0)

        angle = float(i) * (math.pi / 12.0)
        assert (child.target_offset_x or 0.0) == pytest.approx(math.cos(angle) * 100.0, abs=1e-4)
        assert (child.target_offset_y or 0.0) == pytest.approx(math.sin(angle) * 100.0, abs=1e-4)

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
    assert parent.tint == (0.99, 0.99, 0.21, 1.0)
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
        assert child.tint == (0.6, 0.6, 0.31, 1.0)

        angle = float(2 + 2 * i) * (math.pi / 8.0)
        assert child.pos.x == pytest.approx(100.0 + math.cos(angle) * 256.0, abs=1e-4)
        assert child.pos.y == pytest.approx(200.0 + math.sin(angle) * 256.0, abs=1e-4)

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


def test_spawn_plan_porting_is_complete() -> None:
    # creature_spawn_template uses template ids in range 0x00..0x43 (0x44 total),
    # but 0x02 is not present in the switch/decompile extracts.
    expected = frozenset(set(range(0x44)) - {0x02})
    actual = frozenset(entry.spawn_id for entry in SPAWN_TEMPLATES)
    assert actual == expected
