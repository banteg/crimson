from __future__ import annotations

from crimson.creatures.spawn import SpawnId
from crimson.quests.level import QuestLevel
from crimson.quests.runtime import (
    apply_hardcore_spawn_table_adjustment,
    build_quest_spawn_table,
)
from crimson.quests.tier3 import build_3_3_the_killing
from crimson.quests.types import QuestContext, QuestDefinition, SpawnEntry
from crimson.rng_caller_static import RngCallerStatic
from crimson.terrain_slots import DEFAULT_TERRAIN_SLOTS
from crimson.weapons import WeaponId
from grim.geom import Vec2
from grim.rand import Crand, CrandLike
from tests.support.helpers import ScriptedCrand


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


def test_build_3_3_the_killing_matches_native_random_selectors_and_spawner_coords() -> None:
    ctx = QuestContext(width=1024, height=1024, player_count=1)
    rng = ScriptedCrand(
        [
            0,
            0,
            1,
            1,
            2,
            2,
            0,
            3,
            1,
            4,
            10,
            11,
            12,
            13,
            14,
            15,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ],
    )

    entries = build_3_3_the_killing(ctx, rng=rng, full_version=True)

    assert [(entry.spawn_id, entry.trigger_ms) for entry in entries[:7]] == [
        (SpawnId.AI1_ALIEN_BLUE_TINT_1A, 2000),
        (SpawnId.AI1_SPIDER_SP1_BLUE_TINT_1B, 8000),
        (SpawnId.AI1_LIZARD_BLUE_TINT_1C, 14000),
        (SpawnId.AI1_ALIEN_BLUE_TINT_1A, 20000),
        (SpawnId.ALIEN_SPAWNER_CHILD_1D_FAST_07, 26000),
        (SpawnId.ALIEN_SPAWNER_CHILD_1D_FAST_07, 27000),
        (SpawnId.ALIEN_SPAWNER_CHILD_1D_FAST_07, 28000),
    ]
    assert [(entry.pos.x, entry.pos.y) for entry in entries[4:7]] == [
        (139.0, 138.0),
        (141.0, 140.0),
        (143.0, 142.0),
    ]
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.QUEST_BUILD_THE_KILLING_TEMPLATE_PICK,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_LAYOUT_PICK,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_TEMPLATE_PICK,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_LAYOUT_PICK,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_TEMPLATE_PICK,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_LAYOUT_PICK,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_TEMPLATE_PICK,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_LAYOUT_PICK,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_TEMPLATE_PICK,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_LAYOUT_PICK,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_SPAWNER_1_Y,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_SPAWNER_1_X,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_SPAWNER_2_Y,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_SPAWNER_2_X,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_SPAWNER_3_Y,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_SPAWNER_3_X,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_TEMPLATE_PICK,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_LAYOUT_PICK,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_TEMPLATE_PICK,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_LAYOUT_PICK,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_TEMPLATE_PICK,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_LAYOUT_PICK,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_TEMPLATE_PICK,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_LAYOUT_PICK,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_TEMPLATE_PICK,
        RngCallerStatic.QUEST_BUILD_THE_KILLING_LAYOUT_PICK,
    ]
