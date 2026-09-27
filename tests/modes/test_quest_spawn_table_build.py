from __future__ import annotations

from crimson.creatures.spawn import SpawnId
from crimson.quests import quest_by_level
from crimson.quests.level import QuestLevel
from crimson.quests.runtime import (
    apply_hardcore_spawn_table_adjustment,
    build_quest_spawn_table,
)
from crimson.quests.tier1 import (
    build_1_3_target_practice,
    build_1_6_the_random_factor,
)
from crimson.quests.tier2 import (
    build_2_5_sweep_stakes,
)
from crimson.quests.tier3 import build_3_3_the_killing, build_3_9_deja_vu
from crimson.quests.tier4 import build_4_10_the_end_of_all
from crimson.quests.types import QuestContext, SpawnEntry
from crimson.rng_caller_static import RngCallerStatic
from grim.geom import Vec2
from grim.rand import Crand
from tests.support.helpers import ScriptedCrand


def test_end_of_all_hardcore_ring_keeps_native_float32_positions() -> None:
    entries = build_4_10_the_end_of_all(
        QuestContext(player_count=1, hardcore=True),
        rng=Crand(0),
        )
    # Native float32 ring positions, untruncated (oracle-checked).
    assert entries[26].pos == Vec2(332.0, 511.9999694824219)
    assert entries[31].pos == Vec2(667.8845825195312, 422.00006103515625)


def test_apply_hardcore_spawn_table_adjustment() -> None:
    entries = [
        SpawnEntry(
            pos=Vec2(),
            heading=0.0,
            spawn_id=SpawnId.ALIEN_DEADLY_FAST_2B,
            trigger_ms=0,
            count=2,
        ),
        SpawnEntry(
            pos=Vec2(),
            heading=0.0,
            spawn_id=SpawnId.SPIDER_PLASMA_SHOOTER_3C,
            trigger_ms=0,
            count=2,
        ),
        SpawnEntry(
            pos=Vec2(),
            heading=0.0,
            spawn_id=SpawnId.ALIEN_SMALL_GRAY_26,
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
    ctx = QuestContext(player_count=1)
    hardcore_ctx = QuestContext(player_count=1, hardcore=True)
    cases = (
        (QuestLevel(2, 10), 3, 6),
        (QuestLevel(4, 7), 68, 92),
        (QuestLevel(4, 8), 40, 56),
        (QuestLevel(4, 10), 25, 37),
    )

    for level, normal_count, hardcore_count in cases:
        quest = quest_by_level(level)
        assert quest is not None
        normal = build_quest_spawn_table(
            quest,
            ctx,
            rng=Crand(0),
        )
        hardcore = build_quest_spawn_table(
            quest,
            hardcore_ctx,
            rng=Crand(0),
        )

        assert len(normal) == normal_count
        assert len(hardcore) == hardcore_count


def test_build_3_3_the_killing_discards_pick_rolls_and_cycles_by_wave_index() -> None:
    """Native bug (0x4384a0): both per-wave picks roll `crt_rand()` but branch
    on the wave counter, so templates cycle wave % 3, edges cycle wave % 5,
    and the random-spawner batches always land on waves 4 and 9."""

    ctx = QuestContext(player_count=1)
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

    entries = build_3_3_the_killing(ctx, rng=rng)

    assert [(entry.spawn_id, entry.trigger_ms) for entry in entries] == [
        (SpawnId.AI1_ALIEN_BLUE_TINT_1A, 2000),
        (SpawnId.AI1_SPIDER_SP1_BLUE_TINT_1B, 8000),
        (SpawnId.AI1_LIZARD_BLUE_TINT_1C, 14000),
        (SpawnId.AI1_ALIEN_BLUE_TINT_1A, 20000),
        (SpawnId.DEN_ALIEN_BASIC_07, 26000),
        (SpawnId.DEN_ALIEN_BASIC_07, 27000),
        (SpawnId.DEN_ALIEN_BASIC_07, 28000),
        (SpawnId.AI1_LIZARD_BLUE_TINT_1C, 32000),
        (SpawnId.AI1_ALIEN_BLUE_TINT_1A, 38000),
        (SpawnId.AI1_SPIDER_SP1_BLUE_TINT_1B, 44000),
        (SpawnId.AI1_LIZARD_BLUE_TINT_1C, 50000),
        (SpawnId.DEN_ALIEN_BASIC_07, 56000),
        (SpawnId.DEN_ALIEN_BASIC_07, 57000),
        (SpawnId.DEN_ALIEN_BASIC_07, 58000),
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
    ctx = QuestContext(player_count=1)

    target_practice_rng = ScriptedCrand([0], fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    build_1_3_target_practice(ctx, rng=target_practice_rng)
    assert [record.caller for record in target_practice_rng.records_since()] == [
        RngCallerStatic.QUEST_BUILD_TARGET_PRACTICE_ANGLE,
        RngCallerStatic.QUEST_BUILD_TARGET_PRACTICE_RADIUS,
    ] * 30

    random_factor_rng = ScriptedCrand([0], fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    build_1_6_the_random_factor(ctx, rng=random_factor_rng)
    assert [record.caller for record in random_factor_rng.records_since()] == [
        RngCallerStatic.QUEST_BUILD_THE_RANDOM_FACTOR_ALIEN_BIG_GRAY_GATE,
    ] * 10

    sweep_stakes_rng = ScriptedCrand([0], fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    build_2_5_sweep_stakes(ctx, rng=sweep_stakes_rng)
    assert [record.caller for record in sweep_stakes_rng.records_since()] == [
        RngCallerStatic.QUEST_BUILD_SWEEP_STAKES_ANGLE,
    ] * 16

    deja_vu_rng = ScriptedCrand([0], fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    build_3_9_deja_vu(ctx, rng=deja_vu_rng)
    assert [record.caller for record in deja_vu_rng.records_since()] == [
        RngCallerStatic.QUEST_BUILD_DEJA_VU_ANGLE,
    ] * 18
