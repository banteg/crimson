from __future__ import annotations

import random

from grim.geom import Vec2

from ..perks import PerkId
from ..creatures.spawn import SpawnId
from .helpers import (
    center_point,
    edge_midpoints,
    heading_from_center,
    line_points,
    random_angle,
    radial_points,
    spawn,
    spawn_at,
)
from .registry import register_quest
from .types import QuestContext, SpawnEntry


@register_quest(
    level="2.1",
    title="Everred Pastures",
    time_limit_ms=300000,
    start_weapon_id=1,
    unlock_perk_id=PerkId.BONUS_ECONOMIST,
    builder_address=0x004375A0,
)
def build_2_1_everred_pastures(ctx: QuestContext) -> list[SpawnEntry]:
    edges = edge_midpoints(ctx.width)
    entries: list[SpawnEntry] = []
    for wave in range(1, 9):
        trigger = (wave - 1) * 13000 + 1500
        count = wave
        entries.append(
            spawn_at(
                edges.right,
                heading=0.0,
                spawn_id=SpawnId.SPIDER_SP1_RANDOM_32,
                trigger_ms=trigger,
                count=count,
            )
        )
        entries.append(
            spawn_at(
                edges.left,
                heading=0.0,
                spawn_id=SpawnId.SPIDER_SP1_RANDOM_RED_33,
                trigger_ms=trigger,
                count=count,
            )
        )
        entries.append(
            spawn_at(
                edges.bottom,
                heading=0.0,
                spawn_id=SpawnId.SPIDER_SP1_RANDOM_GREEN_34,
                trigger_ms=trigger,
                count=count,
            )
        )
        entries.append(
            spawn_at(
                edges.top,
                heading=0.0,
                spawn_id=SpawnId.SPIDER_SP2_RANDOM_35,
                trigger_ms=trigger,
                count=count,
            )
        )
        if wave == 4:
            entries.append(
                spawn_at(
                    edges.top,
                    heading=0.0,
                    spawn_id=SpawnId.AI1_SPIDER_SP1_BLUE_TINT_1B,
                    trigger_ms=40500,
                    count=8,
                )
            )
            entries.append(
                spawn_at(
                    edges.bottom,
                    heading=0.0,
                    spawn_id=SpawnId.AI1_SPIDER_SP1_BLUE_TINT_1B,
                    trigger_ms=40500,
                    count=8,
                )
            )
    return entries


@register_quest(
    level="2.2",
    title="Spider Spawns",
    time_limit_ms=300000,
    start_weapon_id=1,
    unlock_weapon_id=0x09,
    builder_address=0x00436D70,
)
def build_2_2_spider_spawns(ctx: QuestContext) -> list[SpawnEntry]:
    return [
        spawn(
            Vec2(128.0, 128.0),
            heading=0.0,
            spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_32_FAST_10,
            trigger_ms=1500,
            count=1,
        ),
        spawn(
            Vec2(896.0, 896.0),
            heading=0.0,
            spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_32_FAST_10,
            trigger_ms=1500,
            count=1,
        ),
        spawn(
            Vec2(896.0, 128.0),
            heading=0.0,
            spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_32_FAST_10,
            trigger_ms=1500,
            count=1,
        ),
        spawn(
            Vec2(128.0, 896.0),
            heading=0.0,
            spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_32_FAST_10,
            trigger_ms=1500,
            count=1,
        ),
        spawn(
            Vec2(-64.0, 512.0),
            heading=0.0,
            spawn_id=SpawnId.SPIDER_SP1_AI7_TIMER_38,
            trigger_ms=3000,
            count=2,
        ),
        spawn(
            Vec2(512.0, 512.0),
            heading=0.0,
            spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_32_SLOW_0A,
            trigger_ms=18000,
            count=1,
        ),
        spawn(
            Vec2(448.0, 448.0),
            heading=0.0,
            spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_32_FAST_10,
            trigger_ms=20500,
            count=1,
        ),
        spawn(
            Vec2(576.0, 448.0),
            heading=0.0,
            spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_32_FAST_10,
            trigger_ms=26000,
            count=1,
        ),
        spawn(
            Vec2(1088.0, 512.0),
            heading=0.0,
            spawn_id=SpawnId.SPIDER_SP1_AI7_TIMER_38,
            trigger_ms=21000,
            count=2,
        ),
        spawn(
            Vec2(576.0, 576.0),
            heading=0.0,
            spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_32_FAST_10,
            trigger_ms=31500,
            count=1,
        ),
        spawn(
            Vec2(448.0, 576.0),
            heading=0.0,
            spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_32_FAST_10,
            trigger_ms=22000,
            count=1,
        ),
    ]


@register_quest(
    level="2.3",
    title="Arachnoid Farm",
    time_limit_ms=240000,
    start_weapon_id=1,
    unlock_perk_id=PerkId.THICK_SKINNED,
    builder_address=0x00436820,
)
def build_2_3_arachnoid_farm(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    if ctx.player_count + 4 >= 0:
        trigger = 500
        for pos in line_points(Vec2(256.0, 256.0), Vec2(102.4, 0.0), ctx.player_count + 4):
            entries.append(
                spawn(
                    pos,
                    heading=0.0,
                    spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_32_SLOW_0A,
                    trigger_ms=trigger,
                    count=1,
                )
            )
            trigger += 500
        trigger = 10500
        for pos in line_points(Vec2(256.0, 768.0), Vec2(102.4, 0.0), ctx.player_count + 4):
            entries.append(
                spawn(
                    pos,
                    heading=0.0,
                    spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_32_SLOW_0A,
                    trigger_ms=trigger,
                    count=1,
                )
            )
            trigger += 500
    if ctx.player_count + 7 >= 0:
        trigger = 40500
        for pos in line_points(Vec2(256.0, 512.0), Vec2(64.0, 0.0), ctx.player_count + 7):
            entries.append(
                spawn(
                    pos,
                    heading=0.0,
                    spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_32_FAST_10,
                    trigger_ms=trigger,
                    count=1,
                )
            )
            trigger += 3500
    return entries


@register_quest(
    level="2.4",
    title="Two Fronts",
    time_limit_ms=240000,
    start_weapon_id=1,
    unlock_weapon_id=0x15,
    builder_address=0x00436EE0,
)
def build_2_4_two_fronts(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    edges = edge_midpoints(ctx.width)
    for wave in range(0, 40):
        trigger_a = wave * 2000 + 1000
        trigger_b = (wave * 5 + 5) * 400
        entries.append(
            spawn_at(
                edges.right,
                heading=0.0,
                spawn_id=SpawnId.AI1_ALIEN_BLUE_TINT_1A,
                trigger_ms=trigger_a,
                count=1,
            )
        )
        entries.append(
            spawn_at(
                edges.left,
                heading=0.0,
                spawn_id=SpawnId.AI1_SPIDER_SP1_BLUE_TINT_1B,
                trigger_ms=trigger_b,
                count=1,
            )
        )
        if wave in (10, 20):
            trigger = wave * 2000 + 2500
            entries.append(
                spawn(
                    Vec2(256.0, 256.0),
                    heading=0.0,
                    spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_32_SLOW_0A,
                    trigger_ms=trigger,
                    count=1,
                )
            )
            entries.append(
                spawn(
                    Vec2(768.0, 768.0),
                    heading=0.0,
                    spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_1D_FAST_07,
                    trigger_ms=trigger,
                    count=1,
                )
            )
        if wave == 30:
            trigger = 62500
            entries.append(
                spawn(
                    Vec2(768.0, 256.0),
                    heading=0.0,
                    spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_32_SLOW_0A,
                    trigger_ms=trigger,
                    count=1,
                )
            )
            entries.append(
                spawn(
                    Vec2(256.0, 768.0),
                    heading=0.0,
                    spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_1D_FAST_07,
                    trigger_ms=trigger,
                    count=1,
                )
            )
    return entries


@register_quest(
    level="2.5",
    title="Sweep Stakes",
    time_limit_ms=35000,
    start_weapon_id=6,
    unlock_perk_id=PerkId.BARREL_GREASER,
    builder_address=0x00437810,
)
def build_2_5_sweep_stakes(ctx: QuestContext, rng: random.Random | None = None) -> list[SpawnEntry]:
    rng = rng or random.Random()
    entries: list[SpawnEntry] = []
    center = center_point(ctx.width, ctx.height)
    trigger = 2000
    step = 2000
    while step > 720:
        angle = random_angle(rng)
        for pos in radial_points(center, angle, 0x54, 0xFC, 0x2A):
            heading = heading_from_center(pos, center)
            entries.append(
                spawn(
                    pos,
                    heading=heading,
                    spawn_id=SpawnId.ALIEN_AI7_ORBITER_36,
                    trigger_ms=trigger,
                    count=1,
                )
            )
        trigger += max(step, 600)
        step -= 0x50
    return entries


@register_quest(
    level="2.6",
    title="Evil Zombies At Large",
    time_limit_ms=180000,
    start_weapon_id=1,
    unlock_weapon_id=0x07,
    builder_address=0x004374A0,
)
def build_2_6_evil_zombies_at_large(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    edges = edge_midpoints(ctx.width)
    trigger = 1500
    count = 4
    while count <= 13:
        entries.append(
            spawn_at(
                edges.right,
                heading=0.0,
                spawn_id=SpawnId.ZOMBIE_RANDOM_41,
                trigger_ms=trigger,
                count=count,
            )
        )
        entries.append(
            spawn_at(
                edges.left,
                heading=0.0,
                spawn_id=SpawnId.ZOMBIE_RANDOM_41,
                trigger_ms=trigger,
                count=count,
            )
        )
        entries.append(
            spawn_at(
                edges.bottom,
                heading=0.0,
                spawn_id=SpawnId.ZOMBIE_RANDOM_41,
                trigger_ms=trigger,
                count=count,
            )
        )
        entries.append(
            spawn_at(
                edges.top,
                heading=0.0,
                spawn_id=SpawnId.ZOMBIE_RANDOM_41,
                trigger_ms=trigger,
                count=count,
            )
        )
        trigger += 5500
        count += 1
    return entries


@register_quest(
    level="2.7",
    title="Survival Of The Fastest",
    time_limit_ms=120000,
    start_weapon_id=5,
    unlock_perk_id=PerkId.AMMUNITION_WITHIN,
    builder_address=0x00437060,
)
def build_2_7_survival_of_the_fastest(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry | None] = [None] * 26

    def set_entry(idx: int, pos: Vec2, spawn_id: SpawnId, trigger: int, count: int) -> None:
        if idx < 0 or idx >= len(entries):
            return
        entries[idx] = spawn(pos, heading=0.0, spawn_id=spawn_id, trigger_ms=trigger, count=count)

    # Loop 1: x from 256 to <688, step 72
    trigger = 500
    idx = 0
    for x in range(0x100, 0x2B0, 0x48):
        set_entry(idx, Vec2(float(x), 256.0), SpawnId.ALIEN_SPAWNER_CHILD_32_FAST_10, trigger, 1)
        trigger += 900
        idx += 1

    # Loop 2: y from 256 to <688, step 72, starting at index 6
    trigger = 5900
    idx = 6
    for y in range(0x100, 0x2B0, 0x48):
        set_entry(idx, Vec2(688.0, float(y)), SpawnId.ALIEN_SPAWNER_CHILD_32_FAST_10, trigger, 1)
        trigger += 900
        idx += 1

    # Loop 3: x descending from 688, y=688, starting at index 12
    trigger = 11300
    idx = 12
    for x in (0x2B0, 0x268, 0x220, 0x1D8):
        set_entry(idx, Vec2(float(x), 688.0), SpawnId.ALIEN_SPAWNER_CHILD_32_FAST_10, trigger, 1)
        trigger += 900
        idx += 1

    # Loop 4: y descending from 688, x=400, starting at index 16
    trigger = 14900
    idx = 16
    for y in (0x2B0, 0x268, 0x220, 0x1D8):
        set_entry(idx, Vec2(400.0, float(y)), SpawnId.ALIEN_SPAWNER_CHILD_32_FAST_10, trigger, 1)
        trigger += 900
        idx += 1

    # Loop 5: x from 400 to <544, y=400, starting at index 20
    trigger = 18500
    idx = 20
    for x in range(400, 0x220, 0x48):
        set_entry(idx, Vec2(float(x), 400.0), SpawnId.ALIEN_SPAWNER_CHILD_32_FAST_10, trigger, 1)
        trigger += 900
        idx += 1

    # Final fixed entries
    set_entry(22, Vec2(128.0, 128.0), SpawnId.ALIEN_SPAWNER_CHILD_32_FAST_10, 22300, 1)
    set_entry(23, Vec2(896.0, 128.0), SpawnId.ALIEN_SPAWNER_CHILD_1D_FAST_07, 22300, 1)
    set_entry(24, Vec2(128.0, 896.0), SpawnId.ALIEN_SPAWNER_CHILD_1D_FAST_07, 24300, 1)
    set_entry(25, Vec2(896.0, 896.0), SpawnId.ALIEN_SPAWNER_CHILD_32_FAST_10, 24300, 1)

    return [entry for entry in entries if entry is not None]


@register_quest(
    level="2.8",
    title="Land Of Lizards",
    time_limit_ms=180000,
    start_weapon_id=1,
    unlock_weapon_id=0x04,
    builder_address=0x00437BA0,
)
def build_2_8_land_of_lizards(ctx: QuestContext) -> list[SpawnEntry]:
    return [
        spawn(
            Vec2(256.0, 256.0),
            heading=0.0,
            spawn_id=SpawnId.ALIEN_SPAWNER_RING_24_0E,
            trigger_ms=2000,
            count=1,
        ),
        spawn(
            Vec2(768.0, 256.0),
            heading=0.0,
            spawn_id=SpawnId.ALIEN_SPAWNER_RING_24_0E,
            trigger_ms=12000,
            count=1,
        ),
        spawn(
            Vec2(256.0, 768.0),
            heading=0.0,
            spawn_id=SpawnId.ALIEN_SPAWNER_RING_24_0E,
            trigger_ms=22000,
            count=1,
        ),
        spawn(
            Vec2(768.0, 768.0),
            heading=0.0,
            spawn_id=SpawnId.ALIEN_SPAWNER_RING_24_0E,
            trigger_ms=32000,
            count=1,
        ),
    ]


@register_quest(
    level="2.9",
    title="Ghost Patrols",
    time_limit_ms=180000,
    start_weapon_id=1,
    unlock_perk_id=PerkId.VEINS_OF_POISON,
    builder_address=0x00436200,
)
def build_2_9_ghost_patrols(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    edges = edge_midpoints(ctx.width, ctx.height, offset=128.0)
    entries.append(
        spawn_at(edges.right, heading=0.0, spawn_id=SpawnId.ALIEN_CONST_RED_FAST_2B, trigger_ms=1500, count=2)
    )
    trigger = 2500
    for i in range(12):
        x = edges.left.x if i % 2 == 0 else edges.right.x
        entries.append(
            spawn(
                Vec2(x, edges.left.y),
                heading=0.0,
                spawn_id=SpawnId.FORMATION_RING_ALIEN_5_19,
                trigger_ms=trigger,
                count=1,
            )
        )
        trigger += 2500
    loop_count = 12
    entries.append(
        spawn(
            Vec2(-264.0, edges.left.y),
            heading=0.0,
            spawn_id=SpawnId.ALIEN_CONST_RED_FAST_2B,
            trigger_ms=(loop_count - 1) * 2500,
            count=1,
        )
    )
    special_trigger = (5 * loop_count + 15) * 500
    entries.append(
        spawn(
            Vec2(edges.left.x, edges.left.y),
            heading=0.0,
            spawn_id=SpawnId.FORMATION_GRID_ALIEN_BRONZE_18,
            trigger_ms=special_trigger,
            count=1,
        )
    )
    return entries


@register_quest(
    level="2.10",
    title="Spideroids",
    time_limit_ms=360000,
    start_weapon_id=1,
    unlock_weapon_id=0x0B,
    builder_address=0x004373C0,
)
def build_2_10_spideroids(ctx: QuestContext, full_version: bool = True) -> list[SpawnEntry]:
    entries = [
        spawn(
            Vec2(1088.0, 512.0),
            heading=0.0,
            spawn_id=SpawnId.SPIDER_SP2_SPLITTER_01,
            trigger_ms=1000,
            count=1,
        ),
        spawn(Vec2(-64.0, 512.0), heading=0.0, spawn_id=SpawnId.SPIDER_SP2_SPLITTER_01, trigger_ms=3000, count=1),
        spawn(
            Vec2(1088.0, 256.0),
            heading=0.0,
            spawn_id=SpawnId.SPIDER_SP2_SPLITTER_01,
            trigger_ms=6000,
            count=1,
        ),
    ]
    if full_version:
        entries.append(
            spawn(
                Vec2(1088.0, 762.0),
                heading=0.0,
                spawn_id=SpawnId.SPIDER_SP2_SPLITTER_01,
                trigger_ms=9000,
                count=1,
            )
        )
        entries.append(
            spawn(
                Vec2(512.0, 1088.0),
                heading=0.0,
                spawn_id=SpawnId.SPIDER_SP2_SPLITTER_01,
                trigger_ms=9000,
                count=1,
            )
        )
    if ctx.player_count >= 2 or full_version:
        entries.append(
            spawn(
                Vec2(-64.0, 762.0),
                heading=0.0,
                spawn_id=SpawnId.SPIDER_SP2_SPLITTER_01,
                trigger_ms=9000,
                count=1,
            )
        )
    return entries


__all__ = [
    "QuestContext",
    "SpawnEntry",
    "build_2_1_everred_pastures",
    "build_2_2_spider_spawns",
    "build_2_3_arachnoid_farm",
    "build_2_4_two_fronts",
    "build_2_5_sweep_stakes",
    "build_2_6_evil_zombies_at_large",
    "build_2_7_survival_of_the_fastest",
    "build_2_8_land_of_lizards",
    "build_2_9_ghost_patrols",
    "build_2_10_spideroids",
]
