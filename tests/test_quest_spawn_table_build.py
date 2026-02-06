from __future__ import annotations

import random

from crimson.creatures.spawn import SpawnId
from grim.geom import Vec2
from crimson.quests.runtime import (
    apply_hardcore_spawn_table_adjustment,
    build_quest_spawn_table,
)
from crimson.quests.types import QuestContext, QuestDefinition, SpawnEntry


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
    def builder(ctx: QuestContext, rng: random.Random | None = None, full_version: bool = True) -> list[SpawnEntry]:
        del ctx
        rng = rng or random.Random()
        trigger = rng.randrange(10_000)
        count = 1 if full_version else 2
        return [
            SpawnEntry(
                pos=Vec2(1.0, 2.0),
                heading=0.0,
                spawn_id=SpawnId.ALIEN_CONST_PALE_GREEN_26,
                trigger_ms=trigger,
                count=count,
            )
        ]

    quest = QuestDefinition(level="1.1", title="dummy", builder=builder, time_limit_ms=1000, start_weapon_id=0)
    ctx = QuestContext(width=1024, height=1024, player_count=1)

    full_entries = build_quest_spawn_table(quest, ctx, seed=123, hardcore=False, full_version=True)
    demo_entries = build_quest_spawn_table(quest, ctx, seed=123, hardcore=False, full_version=False)

    assert len(full_entries) == 1
    assert len(demo_entries) == 1
    assert full_entries[0].trigger_ms == demo_entries[0].trigger_ms
    assert full_entries[0].count == 1
    assert demo_entries[0].count == 2
