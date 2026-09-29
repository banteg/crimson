from __future__ import annotations

import pytest

from crimson.creatures.runtime import PHANTOM_CREATURE_INDEX, CreaturePool
from crimson.creatures.spawn import (
    HAS_SPAWN_SLOT_FLAG,
    RANDOM_HEADING_SENTINEL,
    CreatureTypeId,
    SpawnId,
)
from crimson.gameplay import _player_apply_move_with_spawn_avoidance
from crimson.math_parity import f32, x87_pc24_add
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PerkCounts, PlayerState
from grim.color import RGBA
from grim.geom import Vec2
from grim.rand import Crand, RecordingCrand

# Outside the arena: no spawn burst, so the RNG stream is the template's own.
_OFFSCREEN = Vec2(-64.0, 200.0)


def _spawn(
    pool: CreaturePool,
    template_id: SpawnId,
    *,
    seed: int = 0xBEEF,
    pos: Vec2 = _OFFSCREEN,
    heading: float = 0.0,
) -> tuple[int, RecordingCrand]:
    rng = RecordingCrand(Crand(seed))
    returned = pool.spawn_template(template_id, pos, heading, state=GameplayState(rng=rng), detail_preset=5)
    return returned, rng


def _full_pool(free: int = 0) -> CreaturePool:
    pool = CreaturePool()
    for entry in pool.entries[free:]:
        entry.active = True
    return pool


def _phase_seed_draws(rng: RecordingCrand) -> int:
    return sum(record.caller == RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED for record in rng.records)


def test_ring_formation_uses_native_angle_stores_and_fallback() -> None:
    pool = CreaturePool()

    returned, _ = _spawn(pool, SpawnId.FORMATION_RING_ALIEN_8_12, pos=Vec2(100.0, 200.0))

    assert returned == 8
    assert pool.entries[3].target_offset == Vec2(-4.371138857095502e-06, 100.0)
    assert pool.entries[6].target_offset == Vec2(-70.71066284179688, -70.710693359375)
    assert [pool.entries[i].link_index for i in range(1, 9)] == [0] * 8
    assert pool.entries[8].type_id is CreatureTypeId.ALIEN
    assert pool.entries[8].hp == 20.0
    assert pool.entries[8].max_hp == 20.0


def test_second_ring_formation_uses_native_fallback() -> None:
    pool = CreaturePool()

    returned, _ = _spawn(pool, SpawnId.FORMATION_RING_ALIEN_5_19, pos=Vec2(100.0, 200.0))

    assert returned == 5
    assert sum(entry.active for entry in pool.entries) == 6
    assert pool.entries[5].hp == 20.0
    assert pool.entries[5].max_hp == 20.0


def test_chain_formation_uses_native_angle_literals() -> None:
    pool = CreaturePool()

    returned, _ = _spawn(pool, SpawnId.FORMATION_CHAIN_ALIEN_10_13, pos=Vec2(100.0, 200.0))

    assert pool.entries[returned].pos == Vec2(296.1072998046875, 364.5537109375)


def test_formation_members_keep_the_recycled_slots_force_target_and_heading() -> None:
    pool = CreaturePool()
    for entry in pool.entries:
        entry.force_target = 1
        entry.heading = 9.0

    returned, _ = _spawn(pool, SpawnId.FORMATION_CHAIN_ALIEN_10_13, heading=0.75)

    assert pool.entries[0].force_target == 0
    assert [pool.entries[i].force_target for i in range(1, 11)] == [1] * 10
    assert [pool.entries[i].heading for i in range(1, 10)] == [9.0] * 9
    assert pool.entries[returned].heading == 0.75


@pytest.mark.parametrize("template_id", [SpawnId.FORMATION_GRID_ALIEN_GREEN_14, SpawnId.ALIEN_SPAWNER_RING_24_0E])
def test_grid_and_spawner_ring_members_write_a_zero_heading(template_id: SpawnId) -> None:
    pool = CreaturePool()
    for entry in pool.entries:
        entry.heading = 9.0

    returned, _ = _spawn(pool, template_id, heading=0.75)

    assert [pool.entries[i].heading for i in range(1, returned)] == [0.0] * (returned - 1)
    assert pool.entries[returned].heading == 0.75


def test_ring_spawner_keeps_the_recycled_slots_max_health() -> None:
    pool = CreaturePool()
    pool.entries[0].max_hp = 123.0

    _spawn(pool, SpawnId.ALIEN_SPAWNER_RING_24_0E)

    assert pool.entries[0].hp == 50.0
    assert pool.entries[0].max_hp == 123.0


def test_unused_template_02_takes_the_unhandled_type_fallback() -> None:
    pool = CreaturePool()
    stale = pool.entries[0]
    stale.move_speed = 3.0
    stale.size = 33.0
    stale.tint = RGBA(0.25, 0.5, 0.75, 1.0)

    _spawn(pool, SpawnId.UNUSED_02)

    creature = pool.entries[0]
    assert creature.type_id == CreatureTypeId.ALIEN
    assert creature.hp == 20.0
    assert creature.max_hp == 20.0
    assert creature.move_speed == 3.0
    assert creature.size == 33.0
    assert creature.tint == RGBA(0.25, 0.5, 0.75, 1.0)


def test_random_spawn_heading_uses_native_float_literal() -> None:
    pool = CreaturePool()

    returned, _ = _spawn(pool, SpawnId.FORMATION_GRID_ALIEN_GREEN_14, seed=21, heading=RANDOM_HEADING_SENTINEL)

    # Native PC24: the heading roll is 292 and the literal is float32 0.01.
    assert pool.entries[returned].heading == 2.919999837875366


@pytest.mark.parametrize("template_id", [SpawnId(value) for value in range(0x14, 0x19)])
@pytest.mark.parametrize("heading", [0.75, RANDOM_HEADING_SENTINEL])
def test_grid_formation_native_cells_and_random_stream(template_id: SpawnId, heading: float) -> None:
    # Native SPAWN_GRID uses nine columns and three rows, each 64 units apart.
    pool = CreaturePool()
    pos = Vec2(100.0, 200.0)

    returned, rng = _spawn(pool, template_id, pos=pos, heading=heading)

    assert returned == 27
    expected_rng = Crand(0xBEEF)
    assert pool.entries[0].phase_seed == expected_rng.rand() & 0x17F
    if heading == RANDOM_HEADING_SENTINEL:
        expected_rng.rand()
    expected_rng.rand()  # Transient root heading, before any member allocation.
    offsets = [Vec2(float(x), float(y)) for x in range(0, -513, -64) for y in (128, 192, 256)]
    for child, offset in zip(pool.entries[1:28], offsets, strict=True):
        assert child.target_offset == offset
        assert child.pos == Vec2(100.0 + offset.x, 200.0 + offset.y)
        assert child.link_index == 0
        assert child.phase_seed == expected_rng.rand() & 0x17F
    # The last member sits left of the arena: no spawn burst.
    assert rng.state == expected_rng.state
    expected_health = 260.0 if template_id == SpawnId.FORMATION_GRID_ALIEN_BRONZE_18 else 20.0
    assert pool.entries[27].hp == expected_health
    assert pool.entries[27].max_hp == expected_health


def test_full_pool_members_overwrite_the_phantom_slot() -> None:
    pool = _full_pool(free=3)

    returned, rng = _spawn(pool, SpawnId.FORMATION_RING_ALIEN_8_12)

    # The root and two members land in the pool; the other six overwrite the phantom slot,
    # which the tail then treats as the returned creature.
    assert returned == PHANTOM_CREATURE_INDEX
    assert [pool.entries[i].link_index for i in (1, 2)] == [0, 0]
    assert _phase_seed_draws(rng) == 3
    phantom = pool.phantom
    assert phantom.active
    assert phantom.phase_seed == 0
    assert phantom.link_index == 0
    assert phantom.hp == 20.0
    assert phantom.max_hp == 20.0


def test_full_pool_spawn_still_draws_the_template_rng() -> None:
    pool = _full_pool()

    returned, rng = _spawn(pool, SpawnId.ALIEN_RANDOM_1D, heading=RANDOM_HEADING_SENTINEL)

    assert returned == PHANTOM_CREATURE_INDEX
    assert [record.caller for record in rng.records] == [
        RngCallerStatic.CREATURE_SPAWN_TEMPLATE_RANDOM_HEADING,
        RngCallerStatic.CREATURE_SPAWN_TEMPLATE_BASE_HEADING,
        RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1D_SIZE,
        RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1D_MOVE_SPEED,
        RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1D_REWARD,
        RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1D_TINT_R,
        RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1D_TINT_G,
        RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1D_TINT_B,
        RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1D_CONTACT_DAMAGE,
    ]
    assert all(not entry.phase_seed for entry in pool.entries)
    assert pool.creature(PHANTOM_CREATURE_INDEX) is pool.phantom


def test_phantom_spawner_keeps_its_flags_and_spawn_slot_across_spawns() -> None:
    pool = _full_pool()

    _spawn(pool, SpawnId.DEN_ALIEN_BASIC_07)
    assert pool.phantom.flags == HAS_SPAWN_SLOT_FLAG
    assert pool.phantom.link_index == 0
    assert pool.spawn_slots[0].owner_creature == PHANTOM_CREATURE_INDEX
    interval = x87_pc24_add(f32(2.2), f32(0.2))
    assert pool.spawn_slots[0].interval == interval

    # `creature_alloc_slot` never clears the phantom's flags, so a later spawn landing there
    # still reads as a spawner in the tail and stretches the leaked slot's interval again.
    _spawn(pool, SpawnId.ZOMBIE_RANDOM_41)
    assert pool.phantom.type_id is CreatureTypeId.ZOMBIE
    assert pool.phantom.flags == HAS_SPAWN_SLOT_FLAG
    assert pool.spawn_slots[0].interval == x87_pc24_add(interval, f32(0.2))
    assert pool.spawn_slot_alloc() == 1


def test_phantom_spawn_slot_owner_still_blocks_the_player() -> None:
    pool = CreaturePool()
    pool.phantom.pos = Vec2(140.0, 100.0)
    pool.phantom.size = 60.0
    pool.spawn_slots[0].owner_creature = PHANTOM_CREATURE_INDEX
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), size=48.0)

    _player_apply_move_with_spawn_avoidance(player, perks=PerkCounts(), delta=Vec2(5.0, 0.0), creatures=pool)

    assert player.pos == Vec2(100.0, 100.0)


@pytest.mark.parametrize(
    ("template_id", "caller"),
    [
        (SpawnId.AI1_ALIEN_BLUE_TINT_1A, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_AI1_BLUE_TINT_1A),
        (SpawnId.AI1_SPIDER_SP1_BLUE_TINT_1B, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_AI1_BLUE_TINT_1B),
        (SpawnId.AI1_LIZARD_BLUE_TINT_1C, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_AI1_BLUE_TINT_1C),
    ],
)
def test_ai1_blue_tint_uses_exact_native_callers(template_id: SpawnId, caller: RngCallerStatic) -> None:
    _, rng = _spawn(CreaturePool(), template_id, seed=0x1234, heading=RANDOM_HEADING_SENTINEL)

    assert [record.caller for record in rng.records] == [
        RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED,
        RngCallerStatic.CREATURE_SPAWN_TEMPLATE_RANDOM_HEADING,
        RngCallerStatic.CREATURE_SPAWN_TEMPLATE_BASE_HEADING,
        caller,
    ]


_PROLOGUE = [RngCallerStatic.CREATURE_ALLOC_SLOT_PHASE_SEED, RngCallerStatic.CREATURE_SPAWN_TEMPLATE_BASE_HEADING]


@pytest.mark.parametrize(
    ("template_id", "callers"),
    [
        (SpawnId.ALIEN_AI7_ORBITER_36, [RngCallerStatic.CREATURE_SPAWN_TEMPLATE_AI7_ORBITER_TINT_G]),
        (SpawnId.SPIDER_SP2_RANGED_VARIANT_37, [RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP2_RANGED_VARIANT_37_SIZE]),
        (SpawnId.SPIDER_SP1_AI7_TIMER_38, [RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_AI7_TIMER_38_SIZE]),
        (SpawnId.SPIDER_SP1_AI7_TIMER_WEAK_39, [RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_AI7_TIMER_WEAK_39_SIZE]),
        (
            SpawnId.SPIDER_SP1_RANDOM_3D,
            [
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_3D_TINT,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_3D_SIZE,
            ],
        ),
        (
            SpawnId.SPIDER_SP1_RANDOM_03,
            [
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_03_SIZE,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_03_MOVE_SPEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_03_TINT_B,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_03_CONTACT_DAMAGE,
            ],
        ),
        (
            SpawnId.LIZARD_RANDOM_04,
            [
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_04_SIZE,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_04_MOVE_SPEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_04_CONTACT_DAMAGE,
            ],
        ),
        (
            SpawnId.SPIDER_SP2_RANDOM_05,
            [
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP2_RANDOM_05_SIZE,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP2_RANDOM_05_MOVE_SPEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP2_RANDOM_05_TINT_B,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP2_RANDOM_05_CONTACT_DAMAGE,
            ],
        ),
        (
            SpawnId.ALIEN_RANDOM_06,
            [
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_06_SIZE,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_06_MOVE_SPEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_06_TINT_B,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_06_CONTACT_DAMAGE,
            ],
        ),
        (
            SpawnId.ALIEN_RANDOM_1D,
            [
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1D_SIZE,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1D_MOVE_SPEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1D_REWARD,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1D_TINT_R,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1D_TINT_G,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1D_TINT_B,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1D_CONTACT_DAMAGE,
            ],
        ),
        (
            SpawnId.ALIEN_RANDOM_1E,
            [
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1E_SIZE,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1E_MOVE_SPEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1E_REWARD,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1E_TINT_R,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1E_TINT_G,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1E_TINT_B,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1E_CONTACT_DAMAGE,
            ],
        ),
        (
            SpawnId.ALIEN_RANDOM_1F,
            [
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1F_SIZE,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1F_MOVE_SPEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1F_REWARD,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1F_TINT_R,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1F_TINT_G,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1F_TINT_B,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_1F_CONTACT_DAMAGE,
            ],
        ),
        (
            SpawnId.ALIEN_RANDOM_GREEN_20,
            [
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_GREEN_20_SIZE,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_GREEN_20_MOVE_SPEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_GREEN_20_TINT_G,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ALIEN_RANDOM_GREEN_20_CONTACT_DAMAGE,
            ],
        ),
        (
            SpawnId.LIZARD_RANDOM_2E,
            [
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_2E_SIZE,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_2E_MOVE_SPEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_2E_TINT_R,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_2E_TINT_G,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_2E_TINT_B,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_2E_CONTACT_DAMAGE,
            ],
        ),
        (
            SpawnId.LIZARD_RANDOM_31,
            [
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_31_SIZE,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_31_MOVE_SPEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_LIZARD_RANDOM_31_TINT,
            ],
        ),
        (
            SpawnId.SPIDER_SP1_RANDOM_32,
            [
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_32_SIZE,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_32_MOVE_SPEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_32_TINT,
            ],
        ),
        (
            SpawnId.SPIDER_SP1_RANDOM_RED_33,
            [
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_RED_33_SIZE,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_RED_33_MOVE_SPEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_RED_33_TINT_R,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_RED_33_CONTACT_DAMAGE,
            ],
        ),
        (
            SpawnId.SPIDER_SP1_RANDOM_GREEN_34,
            [
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_GREEN_34_SIZE,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_GREEN_34_MOVE_SPEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_GREEN_34_TINT_G,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP1_RANDOM_GREEN_34_CONTACT_DAMAGE,
            ],
        ),
        (
            SpawnId.SPIDER_SP2_RANDOM_35,
            [
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP2_RANDOM_35_SIZE,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP2_RANDOM_35_MOVE_SPEED,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP2_RANDOM_35_TINT_G,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_SPIDER_SP2_RANDOM_35_CONTACT_DAMAGE,
            ],
        ),
        (
            SpawnId.ZOMBIE_RANDOM_41,
            [
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ZOMBIE_RANDOM_41_SIZE,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ZOMBIE_RANDOM_41_TINT,
                RngCallerStatic.CREATURE_SPAWN_TEMPLATE_ZOMBIE_RANDOM_41_CONTACT_DAMAGE,
            ],
        ),
    ],
)
def test_template_rand_sites_use_exact_native_callers(template_id: SpawnId, callers: list[RngCallerStatic]) -> None:
    _, rng = _spawn(CreaturePool(), template_id, seed=0x1234)

    assert [record.caller for record in rng.records] == _PROLOGUE + callers
