from __future__ import annotations

import pytest

from crimson.crand import Crand
from crimson.creatures.spawn import CreatureFlags, CreatureTypeId, build_survival_spawn_creature


def test_survival_spawn_creature_baseline_seed1_xp0() -> None:
    rng = Crand(1)
    c = build_survival_spawn_creature((1.0, 2.0), rng, player_experience=0)

    assert c.type_id == CreatureTypeId.ALIEN
    assert c.flags == CreatureFlags(0)
    assert c.ai_mode == 0

    assert c.size == pytest.approx(44.0, abs=1e-9)
    assert c.heading == pytest.approx(0.15, abs=1e-9)
    assert c.move_speed == pytest.approx(0.9, abs=1e-9)
    assert c.health == pytest.approx(64.0, abs=1e-9)
    assert c.max_health == pytest.approx(64.0, abs=1e-9)
    assert c.contact_damage == pytest.approx(4.19047619047619, abs=1e-9)
    assert c.reward_value == pytest.approx(36.36190476190476, abs=1e-9)

    assert c.tint_r == pytest.approx(0.9, abs=1e-9)
    assert c.tint_g == pytest.approx(0.88, abs=1e-9)
    assert c.tint_b == pytest.approx(0.78, abs=1e-9)
    assert c.tint_a == pytest.approx(1.0, abs=1e-9)

    assert rng.state == 0xC1BBB05F


def test_survival_spawn_creature_xp_threshold_25000_consumes_extra_rand() -> None:
    rng_24999 = Crand(1)
    c_24999 = build_survival_spawn_creature((1.0, 2.0), rng_24999, player_experience=24_999)

    assert c_24999.type_id == CreatureTypeId.SPIDER_SP1
    assert (c_24999.flags & CreatureFlags.AI7_LINK_TIMER) != 0
    assert rng_24999.state == 0xC1BBB05F

    rng_25000 = Crand(1)
    c_25000 = build_survival_spawn_creature((1.0, 2.0), rng_25000, player_experience=25_000)

    assert c_25000.type_id == CreatureTypeId.SPIDER_SP1
    assert (c_25000.flags & CreatureFlags.AI7_LINK_TIMER) != 0
    assert rng_25000.state == 0xA6E9C9A6


def test_survival_spawn_creature_applies_zombie_speed_floor_and_health_scale() -> None:
    rng = Crand(1)
    c = build_survival_spawn_creature((1.0, 2.0), rng, player_experience=90_000)

    assert c.type_id == CreatureTypeId.ZOMBIE
    assert c.flags == CreatureFlags(0)
    assert c.move_speed == pytest.approx(1.3, abs=1e-9)
    assert c.health == pytest.approx(264.75, abs=1e-9)
    assert c.max_health == pytest.approx(264.75, abs=1e-9)
    assert rng.state == 0xC1BBB05F


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
        (0x66, 47.0, 4.476190476190476, 65.0, 256.0, 0.9, 0.4, 0.4, 0xFF51C012),
        (0x51, 57.0, 5.428571428571428, 85.0, 336.0, 0.4, 0.9, 0.4, 0xE157C2DC),
        (0x6A, 56.0, 5.333333333333333, 125.0, 416.0, 0.4, 0.4, 0.9, 0x444FED00),
        # Rare health/size boosts (note: contact_damage is NOT recomputed after the size override).
        (0x422, 80.0, 4.857142857142857, 287.0, 480.0, 0.84, 0.24, 0.89, 0xEC494E99),
        (0x43, 85.0, 4.857142857142857, 2290.0, 720.0, 0.94, 0.84, 0.29, 0x6B953591),
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
    c = build_survival_spawn_creature((1.0, 2.0), rng, player_experience=0)

    assert c.type_id == CreatureTypeId.ALIEN
    assert c.flags == CreatureFlags(0)
    assert c.ai_mode == 0

    assert c.size == pytest.approx(expected_size, abs=1e-9)
    assert c.contact_damage == pytest.approx(expected_contact_damage, abs=1e-9)
    assert c.health == pytest.approx(expected_health, abs=1e-9)
    assert c.max_health == pytest.approx(expected_health, abs=1e-9)
    assert c.reward_value == pytest.approx(expected_reward_value, abs=1e-9)

    assert c.tint_r == pytest.approx(expected_tint_r, abs=1e-9)
    assert c.tint_g == pytest.approx(expected_tint_g, abs=1e-9)
    assert c.tint_b == pytest.approx(expected_tint_b, abs=1e-9)
    assert c.tint_a == pytest.approx(1.0, abs=1e-9)

    assert rng.state == expected_rng_state

