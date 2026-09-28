from __future__ import annotations

from grim.geom import Vec2

from ..creatures.spawn import SpawnId
from ..rng_caller_static import RngCallerStatic
from .helpers import (
    NATIVE_CENTER,
    edge_midpoints,
    heading_from_center,
    line_points,
    radial_points,
    random_angle,
    spawn,
)
from .types import QuestContext, SpawnEntry


def quest_build_everred_pastures(_ctx: QuestContext) -> list[SpawnEntry]:
    edges = edge_midpoints()
    entries: list[SpawnEntry] = []
    for wave in range(1, 9):
        trigger = (wave - 1) * 13000 + 1500
        count = wave
        entries.append(spawn(edges.right, SpawnId.SPIDER_SP1_RANDOM_32, trigger, count))
        entries.append(spawn(edges.left, SpawnId.SPIDER_SP1_RANDOM_RED_33, trigger, count))
        entries.append(spawn(edges.bottom, SpawnId.SPIDER_SP1_RANDOM_GREEN_34, trigger, count))
        entries.append(spawn(edges.top, SpawnId.SPIDER_SP2_RANDOM_35, trigger, count))
        if wave == 4:
            entries.append(spawn(edges.top, SpawnId.AI1_SPIDER_SP1_BLUE_TINT_1B, 40500, 8))
            entries.append(spawn(Vec2(edges.bottom.x, 1088.0), SpawnId.AI1_SPIDER_SP1_BLUE_TINT_1B, 40500, 8))
    return entries


def quest_build_spider_spawns(_ctx: QuestContext) -> list[SpawnEntry]:
    return [
        spawn(Vec2(128.0, 128.0), SpawnId.DEN_SPIDER_WEAK_10, 1500, 1),
        spawn(Vec2(896.0, 896.0), SpawnId.DEN_SPIDER_WEAK_10, 1500, 1),
        spawn(Vec2(896.0, 128.0), SpawnId.DEN_SPIDER_WEAK_10, 1500, 1),
        spawn(Vec2(128.0, 896.0), SpawnId.DEN_SPIDER_WEAK_10, 1500, 1),
        spawn(Vec2(-64.0, 512.0), SpawnId.SPIDER_SP1_AI7_TIMER_38, 3000, 2),
        spawn(Vec2(512.0, 512.0), SpawnId.DEN_SPIDER_BASIC_0A, 18000, 1),
        spawn(Vec2(448.0, 448.0), SpawnId.DEN_SPIDER_WEAK_10, 20500, 1),
        spawn(Vec2(576.0, 448.0), SpawnId.DEN_SPIDER_WEAK_10, 26000, 1),
        spawn(Vec2(1088.0, 512.0), SpawnId.SPIDER_SP1_AI7_TIMER_38, 21000, 2),
        spawn(Vec2(576.0, 576.0), SpawnId.DEN_SPIDER_WEAK_10, 31500, 1),
        spawn(Vec2(448.0, 576.0), SpawnId.DEN_SPIDER_WEAK_10, 22000, 1),
    ]


def quest_build_arachnoid_farm(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    if ctx.player_count + 4 >= 0:
        trigger = 500
        for pos in line_points(Vec2(256.0, 256.0), Vec2(102.4, 0.0), ctx.player_count + 4):
            entries.append(spawn(pos, SpawnId.DEN_SPIDER_BASIC_0A, trigger, 1))
            trigger += 500
        trigger = 10500
        for pos in line_points(Vec2(256.0, 768.0), Vec2(102.4, 0.0), ctx.player_count + 4):
            entries.append(spawn(pos, SpawnId.DEN_SPIDER_BASIC_0A, trigger, 1))
            trigger += 500
    if ctx.player_count + 7 >= 0:
        trigger = 40500
        for pos in line_points(Vec2(256.0, 512.0), Vec2(64.0, 0.0), ctx.player_count + 7):
            entries.append(spawn(pos, SpawnId.DEN_SPIDER_WEAK_10, trigger, 1))
            trigger += 3500
    return entries


def quest_build_two_fronts(_ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    edges = edge_midpoints()
    for wave in range(40):
        trigger_a = wave * 2000 + 1000
        trigger_b = (wave * 5 + 5) * 400
        entries.append(spawn(edges.right, SpawnId.AI1_ALIEN_BLUE_TINT_1A, trigger_a, 1))
        entries.append(spawn(edges.left, SpawnId.AI1_SPIDER_SP1_BLUE_TINT_1B, trigger_b, 1))
        if wave in (10, 20):
            trigger = wave * 2000 + 2500
            entries.append(spawn(Vec2(256.0, 256.0), SpawnId.DEN_SPIDER_BASIC_0A, trigger, 1))
            entries.append(spawn(Vec2(768.0, 768.0), SpawnId.DEN_ALIEN_BASIC_07, trigger, 1))
        if wave == 30:
            trigger = 62500
            entries.append(spawn(Vec2(768.0, 256.0), SpawnId.DEN_SPIDER_BASIC_0A, trigger, 1))
            entries.append(spawn(Vec2(256.0, 768.0), SpawnId.DEN_ALIEN_BASIC_07, trigger, 1))
    return entries


def quest_build_sweep_stakes(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    trigger = 2000
    step = 2000
    while step > 720:
        angle = random_angle(ctx.rng.rand_tagged(RngCallerStatic.QUEST_BUILD_SWEEP_STAKES_ANGLE))
        for pos in radial_points(NATIVE_CENTER, angle, 0x54, 0xFC, 0x2A):
            heading = heading_from_center(pos, NATIVE_CENTER)
            entries.append(spawn(pos, SpawnId.ALIEN_AI7_ORBITER_36, trigger, 1, heading=heading))
        trigger += max(step, 600)
        step -= 0x50
    return entries


def quest_build_evil_zombies_at_large(_ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    edges = edge_midpoints()
    trigger = 1500
    count = 4
    while count <= 13:
        entries.append(spawn(edges.right, SpawnId.ZOMBIE_RANDOM_41, trigger, count))
        entries.append(spawn(edges.left, SpawnId.ZOMBIE_RANDOM_41, trigger, count))
        entries.append(spawn(edges.bottom, SpawnId.ZOMBIE_RANDOM_41, trigger, count))
        entries.append(spawn(edges.top, SpawnId.ZOMBIE_RANDOM_41, trigger, count))
        trigger += 5500
        count += 1
    return entries


def quest_build_survival_of_the_fastest(_ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry | None] = [None] * 26

    def set_entry(idx: int, pos: Vec2, spawn_id: SpawnId, trigger: int, count: int) -> None:
        if idx < 0 or idx >= len(entries):
            return
        entries[idx] = spawn(pos, spawn_id, trigger, count)

    # Loop 1: x from 256 to <688, step 72
    trigger = 500
    for idx, x in enumerate(range(0x100, 0x2B0, 0x48)):
        set_entry(idx, Vec2(float(x), 256.0), SpawnId.DEN_SPIDER_WEAK_10, trigger, 1)
        trigger += 900

    # Loop 2: y from 256 to <688, step 72, starting at index 6
    trigger = 5900
    idx = 6
    for y in range(0x100, 0x2B0, 0x48):
        set_entry(idx, Vec2(688.0, float(y)), SpawnId.DEN_SPIDER_WEAK_10, trigger, 1)
        trigger += 900
        idx += 1

    # Loop 3: x descending from 688, y=688, starting at index 12
    trigger = 11300
    idx = 12
    for x in (0x2B0, 0x268, 0x220, 0x1D8):
        set_entry(idx, Vec2(float(x), 688.0), SpawnId.DEN_SPIDER_WEAK_10, trigger, 1)
        trigger += 900
        idx += 1

    # Loop 4: y descending from 688, x=400, starting at index 16
    trigger = 14900
    idx = 16
    for y in (0x2B0, 0x268, 0x220, 0x1D8):
        set_entry(idx, Vec2(400.0, float(y)), SpawnId.DEN_SPIDER_WEAK_10, trigger, 1)
        trigger += 900
        idx += 1

    # Loop 5: x from 400 to <544, y=400, starting at index 20
    trigger = 18500
    idx = 20
    for x in range(400, 0x220, 0x48):
        set_entry(idx, Vec2(float(x), 400.0), SpawnId.DEN_SPIDER_WEAK_10, trigger, 1)
        trigger += 900
        idx += 1

    # Final fixed entries
    set_entry(22, Vec2(128.0, 128.0), SpawnId.DEN_SPIDER_WEAK_10, 22300, 1)
    set_entry(23, Vec2(896.0, 128.0), SpawnId.DEN_ALIEN_BASIC_07, 22300, 1)
    set_entry(24, Vec2(128.0, 896.0), SpawnId.DEN_ALIEN_BASIC_07, 24300, 1)
    set_entry(25, Vec2(896.0, 896.0), SpawnId.DEN_SPIDER_WEAK_10, 24300, 1)

    return [entry for entry in entries if entry is not None]


def quest_build_land_of_lizards(_ctx: QuestContext) -> list[SpawnEntry]:
    return [
        spawn(Vec2(256.0, 256.0), SpawnId.ALIEN_SPAWNER_RING_24_0E, 2000, 1),
        spawn(Vec2(768.0, 256.0), SpawnId.ALIEN_SPAWNER_RING_24_0E, 12000, 1),
        spawn(Vec2(256.0, 768.0), SpawnId.ALIEN_SPAWNER_RING_24_0E, 22000, 1),
        spawn(Vec2(768.0, 768.0), SpawnId.ALIEN_SPAWNER_RING_24_0E, 32000, 1),
    ]


def quest_build_ghost_patrols(_ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    edges = edge_midpoints(offset=128.0)
    entries.append(spawn(edges.right, SpawnId.ALIEN_DEADLY_FAST_2B, 1500, 2))
    trigger = 2500
    for i in range(12):
        x = edges.left.x if i % 2 == 0 else edges.right.x
        entries.append(spawn(Vec2(x, edges.left.y), SpawnId.FORMATION_RING_ALIEN_5_19, trigger, 1))
        trigger += 2500
    loop_count = 12
    entries.append(spawn(Vec2(-264.0, edges.left.y), SpawnId.ALIEN_DEADLY_FAST_2B, (loop_count - 1) * 2500, 1))
    special_trigger = (5 * loop_count + 15) * 500
    entries.append(spawn(Vec2(edges.left.x, edges.left.y), SpawnId.FORMATION_GRID_ALIEN_BRONZE_18, special_trigger, 1))
    return entries


def quest_build_spideroids(ctx: QuestContext) -> list[SpawnEntry]:
    entries = [
        spawn(Vec2(1088.0, 512.0), SpawnId.SPIDER_SP2_SPLITTER_01, 1000, 1),
        spawn(Vec2(-64.0, 512.0), SpawnId.SPIDER_SP2_SPLITTER_01, 3000, 1),
        spawn(Vec2(1088.0, 256.0), SpawnId.SPIDER_SP2_SPLITTER_01, 6000, 1),
    ]
    if ctx.hardcore:
        entries.append(spawn(Vec2(1088.0, 762.0), SpawnId.SPIDER_SP2_SPLITTER_01, 9000, 1))
        entries.append(spawn(Vec2(512.0, 1088.0), SpawnId.SPIDER_SP2_SPLITTER_01, 9000, 1))
    if ctx.player_count >= 2 or ctx.hardcore:
        entries.append(spawn(Vec2(-64.0, 762.0), SpawnId.SPIDER_SP2_SPLITTER_01, 9000, 1))
    return entries


__all__ = [
    "QuestContext",
    "SpawnEntry",
    "quest_build_arachnoid_farm",
    "quest_build_everred_pastures",
    "quest_build_evil_zombies_at_large",
    "quest_build_ghost_patrols",
    "quest_build_land_of_lizards",
    "quest_build_spider_spawns",
    "quest_build_spideroids",
    "quest_build_survival_of_the_fastest",
    "quest_build_sweep_stakes",
    "quest_build_two_fronts",
]
