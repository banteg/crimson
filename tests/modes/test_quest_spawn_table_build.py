from __future__ import annotations

from crimson.creatures.spawn import SpawnId
from crimson.quests import quest_by_level
from crimson.quests.level import QuestLevel
from crimson.quests.runtime import (
    apply_hardcore_spawn_table_adjustment,
    build_quest_spawn_table,
)
from crimson.quests.tier1 import build_1_3_target_practice, build_1_6_the_random_factor
from crimson.quests.tier2 import build_2_1_everred_pastures, build_2_5_sweep_stakes
from crimson.quests.tier3 import build_3_3_the_killing, build_3_9_deja_vu
from crimson.quests.types import QuestContext, QuestDefinition, SpawnEntry
from crimson.rng_caller_static import RngCallerStatic
from crimson.terrain_slots import DEFAULT_TERRAIN_SLOTS
from crimson.weapons import WeaponId
from grim.geom import Vec2
from grim.rand import Crand, CrandLike
from tests.support.helpers import ScriptedCrand


def test_everred_bonus_bottom_y_is_native_constant() -> None:
    ctx = QuestContext(width=2048, height=2048, player_count=1)

    entries = build_2_1_everred_pastures(ctx, rng=Crand(0), full_version=True)

    assert len(entries) == 34
    assert entries[16].pos == Vec2(1024.0, -64.0)
    assert entries[17].pos == Vec2(1024.0, 1088.0)


def test_apply_hardcore_spawn_table_adjustment() -> None:
    entries = [
        SpawnEntry(
            pos=Vec2(),
            heading=0.0,
            spawn_id=SpawnId.ALIEN_CONST_RED_FAST_2B,
            trigger_ms=0,
            count=2,
        ),
        SpawnEntry(
            pos=Vec2(),
            heading=0.0,
            spawn_id=SpawnId.SPIDER_SP1_CONST_RANGED_VARIANT_3C,
            trigger_ms=0,
            count=2,
        ),
        SpawnEntry(
            pos=Vec2(),
            heading=0.0,
            spawn_id=SpawnId.ALIEN_CONST_PALE_GREEN_26,
            trigger_ms=0,
            count=1,
        ),
    ]

    adjusted = apply_hardcore_spawn_table_adjustment(entries)

    assert [entry.count for entry in adjusted] == [
        4,  # 0x2B gets +2
        2,  # 0x3C excluded
        1,  # count <= 1 excluded
    ]


def test_builder_specific_hardcore_branches_use_runtime_flag() -> None:
    ctx = QuestContext(width=1024, height=1024, player_count=1)
    cases = (
        (QuestLevel(2, 10), 3, 6),
        (QuestLevel(4, 7), 68, 92),
        (QuestLevel(4, 8), 40, 56),
    )

    for level, normal_count, hardcore_count in cases:
        quest = quest_by_level(level)
        assert quest is not None
        normal = build_quest_spawn_table(
            quest,
            ctx,
            rng=Crand(0),
            hardcore=False,
            full_version=True,
        )
        demo = build_quest_spawn_table(
            quest,
            ctx,
            rng=Crand(0),
            hardcore=False,
            full_version=False,
        )
        hardcore = build_quest_spawn_table(
            quest,
            ctx,
            rng=Crand(0),
            hardcore=True,
            full_version=True,
        )

        assert len(normal) == normal_count
        assert len(demo) == normal_count
        assert len(hardcore) == hardcore_count


def test_build_quest_spawn_table_passes_rng_and_full_version() -> None:
    def builder(ctx: QuestContext, *, rng: CrandLike, full_version: bool = True) -> list[SpawnEntry]:
        del ctx
        trigger = int(rng.rand() % 10_000)
        count = 1 if full_version else 2
        return [
            SpawnEntry(
                pos=Vec2(1.0, 2.0),
                heading=0.0,
                spawn_id=SpawnId.ALIEN_CONST_PALE_GREEN_26,
                trigger_ms=trigger,
                count=count,
            ),
        ]

    quest = QuestDefinition(
        level=QuestLevel(1, 1),
        title="dummy",
        builder=builder,
        time_limit_ms=1000,
        start_weapon_id=WeaponId.NONE,
        terrain_slots=DEFAULT_TERRAIN_SLOTS,
    )
    ctx = QuestContext(width=1024, height=1024, player_count=1)

    full_entries = build_quest_spawn_table(quest, ctx, rng=Crand(123), hardcore=False, full_version=True)
    demo_entries = build_quest_spawn_table(quest, ctx, rng=Crand(123), hardcore=False, full_version=False)

    assert len(full_entries) == 1
    assert len(demo_entries) == 1
    assert full_entries[0].trigger_ms == demo_entries[0].trigger_ms
    assert full_entries[0].count == 1
    assert demo_entries[0].count == 2


def test_build_3_3_the_killing_discards_pick_rolls_and_cycles_by_wave_index() -> None:
    """Native bug (0x4384a0): both per-wave picks roll `crt_rand()` but branch
    on the wave counter, so templates cycle wave % 3, edges cycle wave % 5,
    and the random-spawner batches always land on waves 4 and 9."""

    ctx = QuestContext(width=1024, height=1024, player_count=1)
    # Pick rolls of 4 would make every wave a spawner wave if the rolls were
    # used; spawner coordinate rolls are real (y before x, like native).
    rng = ScriptedCrand(
        [
            *([4, 4] * 4),
            4, 4, 10, 11, 12, 13, 14, 15,
            *([4, 4] * 4),
            4, 4, 20, 21, 22, 23, 24, 25,
        ],
    )

    entries = build_3_3_the_killing(ctx, rng=rng, full_version=True)

    assert [(entry.spawn_id, entry.trigger_ms) for entry in entries] == [
        (SpawnId.AI1_ALIEN_BLUE_TINT_1A, 2000),
        (SpawnId.AI1_SPIDER_SP1_BLUE_TINT_1B, 8000),
        (SpawnId.AI1_LIZARD_BLUE_TINT_1C, 14000),
        (SpawnId.AI1_ALIEN_BLUE_TINT_1A, 20000),
        (SpawnId.ALIEN_SPAWNER_CHILD_1D_FAST_07, 26000),
        (SpawnId.ALIEN_SPAWNER_CHILD_1D_FAST_07, 27000),
        (SpawnId.ALIEN_SPAWNER_CHILD_1D_FAST_07, 28000),
        (SpawnId.AI1_LIZARD_BLUE_TINT_1C, 32000),
        (SpawnId.AI1_ALIEN_BLUE_TINT_1A, 38000),
        (SpawnId.AI1_SPIDER_SP1_BLUE_TINT_1B, 44000),
        (SpawnId.AI1_LIZARD_BLUE_TINT_1C, 50000),
        (SpawnId.ALIEN_SPAWNER_CHILD_1D_FAST_07, 56000),
        (SpawnId.ALIEN_SPAWNER_CHILD_1D_FAST_07, 57000),
        (SpawnId.ALIEN_SPAWNER_CHILD_1D_FAST_07, 58000),
    ]
    assert [(entry.pos.x, entry.pos.y) for entry in entries[4:7]] == [
        (139.0, 138.0),
        (141.0, 140.0),
        (143.0, 142.0),
    ]
    assert [(entry.pos.x, entry.pos.y) for entry in entries[11:14]] == [
        (149.0, 148.0),
        (151.0, 150.0),
        (153.0, 152.0),
    ]
    wave_pick_callers = [
        RngCallerStatic.QUEST_BUILD_THE_KILLING_TEMPLATE_PICK,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_LAYOUT_PICK,
    ]
    spawner_callers = [
        RngCallerStatic.QUEST_BUILD_THE_KILLING_SPAWNER_1_Y,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_SPAWNER_1_X,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_SPAWNER_2_Y,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_SPAWNER_2_X,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_SPAWNER_3_Y,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_SPAWNER_3_X,
    ]
    assert [record.caller for record in rng.records_since()] == [
        *wave_pick_callers * 5,
        *spawner_callers,
        *wave_pick_callers * 5,
        *spawner_callers,
    ]


def test_quest_rng_builders_use_exact_native_callers() -> None:
    ctx = QuestContext(width=1024, height=1024, player_count=1)

    target_practice_rng = ScriptedCrand([0], fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    build_1_3_target_practice(ctx, rng=target_practice_rng, full_version=True)
    assert [record.caller for record in target_practice_rng.records_since()] == [
        RngCallerStatic.QUEST_BUILD_TARGET_PRACTICE_ANGLE,
        RngCallerStatic.QUEST_BUILD_TARGET_PRACTICE_RADIUS,
    ] * 30

    random_factor_rng = ScriptedCrand([0], fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    build_1_6_the_random_factor(ctx, rng=random_factor_rng, full_version=True)
    assert [record.caller for record in random_factor_rng.records_since()] == [
        RngCallerStatic.QUEST_BUILD_THE_RANDOM_FACTOR_BRUTE_GATE,
    ] * 10

    sweep_stakes_rng = ScriptedCrand([0], fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    build_2_5_sweep_stakes(ctx, rng=sweep_stakes_rng, full_version=True)
    assert [record.caller for record in sweep_stakes_rng.records_since()] == [
        RngCallerStatic.QUEST_BUILD_SWEEP_STAKES_ANGLE,
    ] * 16

    deja_vu_rng = ScriptedCrand([0], fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    build_3_9_deja_vu(ctx, rng=deja_vu_rng, full_version=True)
    assert [record.caller for record in deja_vu_rng.records_since()] == [
        RngCallerStatic.QUEST_BUILD_DEJA_VU_ANGLE,
    ] * 18
