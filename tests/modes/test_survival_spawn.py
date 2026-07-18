from __future__ import annotations

import pytest

from crimson.creatures.spawn import CreatureFlags, CreatureTypeId, build_survival_spawn_creature
from crimson.math_parity import f32, f32_from_bits
from crimson.rng_caller_static import RngCallerStatic
from grim.geom import Vec2
from grim.rand import Crand
from tests.support.helpers import ScriptedCrand, assert_float_close


def test_survival_spawn_creature_baseline_seed1_xp0() -> None:
    rng = Crand(1)
    c = build_survival_spawn_creature(Vec2(1.0, 2.0), rng, player_experience=0)

    assert c.type_id == CreatureTypeId.ALIEN
    assert c.flags == CreatureFlags(0)
    assert c.ai_mode == 0

    assert_float_close(c.size, 44.0)
    assert_float_close(c.heading, float(f32(f32(15.0) * f32(0.01))))
    assert_float_close(c.move_speed, float(f32(0.9)))
    assert_float_close(c.health, 64.0)
    assert_float_close(c.max_health, 64.0)
    assert c.contact_damage == f32_from_bits(0x40861862)
    assert c.reward_value == f32_from_bits(0x42117297)

    assert c.tint is not None
    assert c.tint == (
        f32_from_bits(0x3F666666),
        f32_from_bits(0x3F6147AD),
        f32_from_bits(0x3F47AE14),
        f32_from_bits(0x3F800000),
    )

    assert rng.state == 0xC1BBB05F


def test_survival_spawn_creature_xp_threshold_25000_consumes_extra_rand() -> None:
    rng_24999 = Crand(1)
    c_24999 = build_survival_spawn_creature(Vec2(1.0, 2.0), rng_24999, player_experience=24_999)

    assert c_24999.type_id == CreatureTypeId.SPIDER_SP1
    assert (c_24999.flags & CreatureFlags.AI7_LINK_TIMER) != 0
    assert rng_24999.state == 0xC1BBB05F

    rng_25000 = Crand(1)
    c_25000 = build_survival_spawn_creature(Vec2(1.0, 2.0), rng_25000, player_experience=25_000)

    assert c_25000.type_id == CreatureTypeId.SPIDER_SP1
    assert (c_25000.flags & CreatureFlags.AI7_LINK_TIMER) != 0
    assert rng_25000.state == 0xA6E9C9A6


def test_survival_spawn_creature_applies_zombie_speed_floor_and_health_scale() -> None:
    rng = Crand(1)
    c = build_survival_spawn_creature(Vec2(1.0, 2.0), rng, player_experience=90_000)

    assert c.type_id == CreatureTypeId.ZOMBIE
    assert c.flags == CreatureFlags(0)
    assert_float_close(c.move_speed, float(f32(1.3)))
    assert_float_close(c.health, 264.75)
    assert_float_close(c.max_health, 264.75)
    assert rng.state == 0xC1BBB05F


def _survival_spawn_exact_values(*, type_roll: int, include_parity: bool) -> list[int]:
    values = [0, type_roll]
    if include_parity:
        values.append(1)
    values.extend(
        [
            0,  # rare override
            0,  # size
            0,  # heading
            0,  # health
            0,  # tint_g
            0,  # tint_b
            0,  # reward bonus
            2,  # rare red
            2,  # rare green
            2,  # rare blue
            4,  # rare purple
            4,  # rare yellow
        ],
    )
    return values


def _expected_survival_spawn_callers(
    *,
    tint_g: RngCallerStatic,
    tint_b: RngCallerStatic,
    include_parity: bool,
) -> list[RngCallerStatic]:
    callers = [
        RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
        RngCallerStatic.SURVIVAL_SPAWN_CREATURE_TYPE_ROLL,
    ]
    if include_parity:
        callers.append(RngCallerStatic.SURVIVAL_SPAWN_CREATURE_PARITY_PICK)
    callers.extend(
        [
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_RARE_OVERRIDE,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_SIZE,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_HEADING,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_HEALTH,
            tint_g,
            tint_b,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_REWARD_BONUS,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_RARE_RED,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_RARE_GREEN,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_RARE_BLUE,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_RARE_PURPLE,
            RngCallerStatic.SURVIVAL_SPAWN_CREATURE_RARE_YELLOW,
        ],
    )
    return callers


def test_survival_spawn_creature_rounds_native_stat_chain_at_each_pc24_operation() -> None:
    values = _survival_spawn_exact_values(type_roll=0, include_parity=False)
    values[8] = 1  # reward bonus becomes 11; this exposes the association difference.
    c = build_survival_spawn_creature(
        Vec2(1.0, 2.0),
        ScriptedCrand(values),
        player_experience=0,
    )

    assert c.contact_damage == f32_from_bits(0x40861862)
    assert c.reward_value == f32_from_bits(0x41FDC677)
    assert c.tint == (
        f32_from_bits(0x3F666666),
        f32_from_bits(0x3F4CCCCC),
        f32_from_bits(0x3F333333),
        f32_from_bits(0x3F800000),
    )


@pytest.mark.parametrize(
    ("xp", "values", "expected_callers"),
    [
        (
            0,
            _survival_spawn_exact_values(type_roll=0, include_parity=False),
            _expected_survival_spawn_callers(
                tint_g=RngCallerStatic.SURVIVAL_SPAWN_CREATURE_LOW_TINT_G,
                tint_b=RngCallerStatic.SURVIVAL_SPAWN_CREATURE_LOW_TINT_B,
                include_parity=False,
            ),
        ),
        (
            25_000,
            _survival_spawn_exact_values(type_roll=5, include_parity=True),
            _expected_survival_spawn_callers(
                tint_g=RngCallerStatic.SURVIVAL_SPAWN_CREATURE_LOW_TINT_G,
                tint_b=RngCallerStatic.SURVIVAL_SPAWN_CREATURE_LOW_TINT_B,
                include_parity=True,
            ),
        ),
        (
            50_000,
            _survival_spawn_exact_values(type_roll=0, include_parity=False),
            _expected_survival_spawn_callers(
                tint_g=RngCallerStatic.SURVIVAL_SPAWN_CREATURE_MID_TINT_G,
                tint_b=RngCallerStatic.SURVIVAL_SPAWN_CREATURE_MID_TINT_B,
                include_parity=False,
            ),
        ),
        (
            100_000,
            _survival_spawn_exact_values(type_roll=0, include_parity=False),
            _expected_survival_spawn_callers(
                tint_g=RngCallerStatic.SURVIVAL_SPAWN_CREATURE_HIGH_TINT_G,
                tint_b=RngCallerStatic.SURVIVAL_SPAWN_CREATURE_HIGH_TINT_B,
                include_parity=False,
            ),
        ),
    ],
)
def test_survival_spawn_creature_uses_exact_native_callers(
    xp: int,
    values: list[int],
    expected_callers: list[RngCallerStatic],
) -> None:
    rng = ScriptedCrand(values)

    build_survival_spawn_creature(Vec2(1.0, 2.0), rng, player_experience=xp)

    assert [record.caller for record in rng.records_since()] == expected_callers


@pytest.mark.parametrize(
    (
        "seed",
        "expected_size",
        "expected_contact_damage",
        "expected_health",
        "expected_reward_value",
        "expected_tint_r",
        "expected_tint_g",
        "expected_tint_b",
        "expected_rng_state",
    ),
    [
        # Rare stat overrides (color-coded variants).
        (0x66, 47.0, 4.476190559566021, 65.0, 256.0, 0.9, 0.4, 0.4, 0xFF51C012),
        (0x51, 57.0, 5.428571529686451, 85.0, 336.0, 0.4, 0.9, 0.4, 0xE157C2DC),
        (0x6A, 56.0, 5.333333432674408, 125.0, 416.0, 0.4, 0.4, 0.9, 0x444FED00),
        # Rare health/size boosts (note: contact_damage is NOT recomputed after the size override).
        (0x422, 80.0, 4.857142947614193, 287.0, 480.0, 0.84, 0.24, 0.89, 0xEC494E99),
        (0x43, 85.0, 4.857142947614193, 2290.0, 720.0, 0.94, 0.84, 0.29, 0x6B953591),
    ],
)
def test_survival_spawn_creature_rare_variants(
    seed: int,
    expected_size: float,
    expected_contact_damage: float,
    expected_health: float,
    expected_reward_value: float,
    expected_tint_r: float,
    expected_tint_g: float,
    expected_tint_b: float,
    expected_rng_state: int,
) -> None:
    rng = Crand(seed)
    c = build_survival_spawn_creature(Vec2(1.0, 2.0), rng, player_experience=0)

    assert c.type_id == CreatureTypeId.ALIEN
    assert c.flags == CreatureFlags(0)
    assert c.ai_mode == 0

    assert_float_close(c.size, expected_size)
    assert c.contact_damage == f32(expected_contact_damage)
    assert_float_close(c.health, expected_health)
    assert_float_close(c.max_health, expected_health)
    assert_float_close(c.reward_value, expected_reward_value)

    assert c.tint is not None
    assert c.tint[0] == f32(expected_tint_r)
    assert c.tint[1] == f32(expected_tint_g)
    assert c.tint[2] == f32(expected_tint_b)
    assert c.tint[3] == f32(1.0)

    assert rng.state == expected_rng_state
