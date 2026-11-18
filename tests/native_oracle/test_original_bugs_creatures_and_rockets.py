"""GOG 1.9.93 creature and rocket regressions for original bugs 62, 63, 68 and 69."""

from __future__ import annotations

import math

import pytest

from crimson.creatures.damage_types import CreatureDamageType
from crimson.creatures.spawn_ids import CreatureFlags, CreatureTypeId, SpawnId
from crimson.projectiles.types import SecondaryProjectileTypeId

from ._support import (
    CREATURE_LAYOUT,
    CREATURE_STRIDE,
    PLAYER_OFFSETS,
    SECONDARY_PROJECTILE_LAYOUT,
    SPAWN_SLOT_LAYOUT,
    install_fake_grim,
    prepare_gameplay,
)


def _spawn(oracle, template: SpawnId, x: float, y: float) -> int:
    return oracle.call("creature_spawn_template", template, oracle.alloc_f32s(x, y), 0.0).eax


def _prepare_corpses(oracle) -> None:
    prepare_gameplay(oracle)
    install_fake_grim(oracle)
    for name in ("cv_bodiesFade", "cv_terrainBodiesTransparency"):
        cvar = oracle.alloc(0x40)
        oracle.write_f32(cvar + 0x0C, 1.0)
        oracle.write_u32(name, cvar)
    player = oracle.resolve("player_state_table")
    oracle.write_f32(player + PLAYER_OFFSETS["health"], 100.0)


def _finish_corpse(oracle, creature: int) -> None:
    creature_type = oracle.read_i32(creature + CREATURE_LAYOUT["type_id"][0])
    for _ in range(120):
        oracle.call("creature_update_all")
        oracle.call("creature_render_type", creature_type, 1.0)
        if not oracle.read_u8(creature):
            return
    pytest.fail("native update and render did not release the corpse")


def test_fading_den_releases_the_live_replacements_spawn_slot(oracle) -> None:
    _prepare_corpses(oracle)
    oracle.write_f32("frame_dt", 1 / 60)
    player = oracle.resolve("player_state_table")
    oracle.write_f32(player + PLAYER_OFFSETS["size"], 35.0)
    slot = oracle.resolve("creature_spawn_slot_table")
    child_template = slot + SPAWN_SLOT_LAYOUT["template_id"][0]
    old_den = _spawn(oracle, SpawnId.DEN_SPIDER_BASIC_0A, 250.0, 250.0)
    assert oracle.read_u32(slot) == old_den
    oracle.call("creature_apply_damage", 0, 100_000.0, CreatureDamageType.EXPLOSION, oracle.alloc_f32s(0.0, 0.0))
    assert oracle.read_u32(slot) == 0

    plasma_den = _spawn(oracle, SpawnId.DEN_SPIDER_PLASMA_SHOOTERS_0B, 700.0, 700.0)
    assert oracle.read_u32(slot) == plasma_den

    def step_toward_plasma_den() -> float:
        position = oracle.alloc_f32s(665.0, 700.0)
        oracle.call("player_apply_move_with_spawn_avoidance", 0, position, oracle.alloc_f32s(6.0, 0.0))
        return oracle.read_f32(position)

    assert step_toward_plasma_den() == 665.0
    _finish_corpse(oracle, old_den)
    assert oracle.read_u8(plasma_den) == 1
    assert oracle.read_u32(slot) == 0
    assert step_toward_plasma_den() == 671.0
    assert oracle.read_i32(child_template) == SpawnId.SPIDER_PLASMA_SHOOTER_3C

    lizard_den = _spawn(oracle, SpawnId.DEN_LIZARD_WEAK_0C, 350.0, 400.0)
    assert oracle.read_u32(slot) == lizard_den
    assert oracle.read_i32(plasma_den + CREATURE_LAYOUT["link_index"][0]) == 0
    assert oracle.read_i32(lizard_den + CREATURE_LAYOUT["link_index"][0]) == 0
    assert oracle.read_i32(child_template) == SpawnId.LIZARD_RANDOM_31

    # With 24 ms on their shared clock, the first den advances it, then the second emits.
    oracle.write_f32(slot + SPAWN_SLOT_LAYOUT["timer"][0], 0.024)
    oracle.write_f32("frame_dt", 0.016)
    oracle.call("creature_update_all")
    assert oracle.read_i32(slot + SPAWN_SLOT_LAYOUT["count"][0]) == 1
    child = oracle.read_fields(oracle.resolve("creature_pool") + 2 * CREATURE_STRIDE, CREATURE_LAYOUT)
    assert child["active"] and child["type_id"] == CreatureTypeId.LIZARD
    assert math.dist((child["pos_x"], child["pos_y"]), (700.0, 700.0)) < 3.0


@pytest.mark.parametrize(("fps", "poison_kills"), [(30, 0), (50, 1), (60, 0)])
def test_poison_can_skip_the_kill_counter_without_losing_xp(oracle, fps: int, poison_kills: int) -> None:
    _prepare_corpses(oracle)
    oracle.write_f32("frame_dt", 1 / fps)
    creature = _spawn(oracle, SpawnId.LIZARD_CONST_GREY_2F, 500.0, 500.0)
    oracle.write_f32(creature + CREATURE_LAYOUT["health"][0], 1.0)
    oracle.write_f32(creature + CREATURE_LAYOUT["reward_value"][0], 100.0)
    initial = oracle.snapshot()
    for flags, expected_kills in [(0, 1), (CreatureFlags.POISONED, poison_kills)]:
        oracle.restore(initial)
        oracle.write_u32(creature + CREATURE_LAYOUT["flags"][0], flags)
        oracle.call("creature_apply_damage", 0, 10.0, CreatureDamageType.BULLET, oracle.alloc_f32s(0.0, 0.0))
        _finish_corpse(oracle, creature)
        assert oracle.read_i32("player_experience") == 100
        assert oracle.read_i32("creature_kill_count") == expected_kills
        assert oracle.read_i32("fx_queue_rotated") == expected_kills


def test_seeker_retains_its_dead_target_until_the_slot_becomes_inactive(oracle) -> None:
    prepare_gameplay(oracle)
    oracle.write_f32("frame_dt", 0.016)
    target = _spawn(oracle, SpawnId.LIZARD_CONST_GREY_2F, 680.0, 500.0)
    _spawn(oracle, SpawnId.LIZARD_CONST_GREY_2F, 500.0, 620.0)
    player = oracle.resolve("player_state_table")
    oracle.write_f32(player + PLAYER_OFFSETS["aim_x"], 680.0)
    oracle.write_f32(player + PLAYER_OFFSETS["aim_y"], 500.0)
    origin = oracle.alloc_f32s(500.0, 500.0)
    oracle.call("fx_spawn_secondary_projectile", origin, 0.0, SecondaryProjectileTypeId.HOMING_ROCKET)
    lock = oracle.resolve("secondary_projectile_pool") + SECONDARY_PROJECTILE_LAYOUT["target_id"][0]
    assert oracle.read_i32(lock) == 0
    oracle.call("creature_apply_damage", 0, 21.0, CreatureDamageType.EXPLOSION, oracle.alloc_f32s(0.0, 0.0))
    assert oracle.read_f32(target + CREATURE_LAYOUT["health"][0]) == -1.0
    assert oracle.read_u8(target) == 1
    oracle.call("projectile_update")
    assert oracle.read_i32(lock) == 0
    oracle.write_u8(target, 0)
    oracle.call("projectile_update")
    assert oracle.read_i32(lock) == 1


@pytest.mark.parametrize(
    ("rocket", "impact_scale"),
    [
        (SecondaryProjectileTypeId.ROCKET, 1.0),
        (SecondaryProjectileTypeId.HOMING_ROCKET, 0.35),
        (SecondaryProjectileTypeId.ROCKET_MINIGUN, 0.25),
    ],
    ids=["launcher", "seeker", "minigun"],
)
def test_expiry_frame_overwrites_the_rocket_impact_scale(oracle, rocket, impact_scale: float) -> None:
    prepare_gameplay(oracle)
    oracle.write_f32("frame_dt", 0.016)
    target = _spawn(oracle, SpawnId.LIZARD_CONST_GREY_2F, 501.0, 500.0)
    oracle.write_f32(target + CREATURE_LAYOUT["health"][0], 5000.0)
    oracle.call("fx_spawn_secondary_projectile", oracle.alloc_f32s(500.0, 500.0), math.pi / 2, rocket)
    projectile = oracle.resolve("secondary_projectile_pool")
    initial = oracle.snapshot()
    for flight_left, expected_scale in [(0.5, impact_scale), (0.005, 0.5)]:
        oracle.restore(initial)
        oracle.write_f32(projectile + SECONDARY_PROJECTILE_LAYOUT["life_timer"][0], flight_left)
        oracle.call("projectile_update")
        assert oracle.read_i32("highscore_record_shots_hit") == 1
        detonation = oracle.read_fields(projectile, SECONDARY_PROJECTILE_LAYOUT)
        assert detonation["type_id"] == SecondaryProjectileTypeId.DETONATION
        # Detonations store their scale in the old Y velocity field.
        assert detonation["vel_y"] == pytest.approx(expected_scale)
