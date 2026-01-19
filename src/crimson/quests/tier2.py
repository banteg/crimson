from __future__ import annotations

import math
import random

from .registry import register_quest
from .types import QuestContext, SpawnEntry

SPAWN_ID_1 = 0x01
SPAWN_ID_7 = 0x07
SPAWN_ID_8 = 0x08
SPAWN_ID_10 = 0x0A
SPAWN_ID_14 = 0x0E
SPAWN_ID_16 = 0x10
SPAWN_ID_24 = 0x18
SPAWN_ID_25 = 0x19
SPAWN_ID_26 = 0x1A
SPAWN_ID_27 = 0x1B
SPAWN_ID_43 = 0x2B
SPAWN_ID_50 = 0x32
SPAWN_ID_51 = 0x33
SPAWN_ID_52 = 0x34
SPAWN_ID_53 = 0x35
SPAWN_ID_54 = 0x36
SPAWN_ID_56 = 0x38
SPAWN_ID_65 = 0x41


@register_quest(
    level="2.1",
    title="Everred Pastures",
    time_limit_ms=300000,
    start_weapon_id=1,
    unlock_perk_id=0x20,
    builder_address=0x004375a0,
)
def build_2_1_everred_pastures(ctx: QuestContext) -> list[SpawnEntry]:
    half_w = ctx.width // 2
    edge_w = ctx.width + 64
    entries: list[SpawnEntry] = []
    for wave in range(1, 9):
        trigger = (wave - 1) * 13000 + 1500
        count = wave
        entries.append(SpawnEntry(edge_w, float(half_w), 0.0, SPAWN_ID_50, trigger, count))
        entries.append(SpawnEntry(-64.0, float(half_w), 0.0, SPAWN_ID_51, trigger, count))
        entries.append(SpawnEntry(float(half_w), float(edge_w), 0.0, SPAWN_ID_52, trigger, count))
        entries.append(SpawnEntry(float(half_w), -64.0, 0.0, SPAWN_ID_53, trigger, count))
        if wave == 4:
            entries.append(SpawnEntry(float(half_w), -64.0, 0.0, SPAWN_ID_27, 40500, 8))
            entries.append(SpawnEntry(float(half_w), float(edge_w), 0.0, SPAWN_ID_27, 40500, 8))
    return entries


@register_quest(
    level="2.2",
    title="Spider Spawns",
    time_limit_ms=300000,
    start_weapon_id=1,
    unlock_weapon_id=0x09,
    builder_address=0x00436d70,
)
def build_2_2_spider_spawns(ctx: QuestContext) -> list[SpawnEntry]:
    return [
        SpawnEntry(128.0, 128.0, 0.0, SPAWN_ID_16, 1500, 1),
        SpawnEntry(896.0, 896.0, 0.0, SPAWN_ID_16, 1500, 1),
        SpawnEntry(896.0, 128.0, 0.0, SPAWN_ID_16, 1500, 1),
        SpawnEntry(128.0, 896.0, 0.0, SPAWN_ID_16, 1500, 1),
        SpawnEntry(-64.0, 512.0, 0.0, SPAWN_ID_56, 3000, 2),
        SpawnEntry(512.0, 512.0, 0.0, SPAWN_ID_10, 18000, 1),
        SpawnEntry(448.0, 448.0, 0.0, SPAWN_ID_16, 20500, 1),
        SpawnEntry(576.0, 448.0, 0.0, SPAWN_ID_16, 26000, 1),
        SpawnEntry(1088.0, 512.0, 0.0, SPAWN_ID_56, 21000, 2),
        SpawnEntry(576.0, 576.0, 0.0, SPAWN_ID_16, 31500, 1),
        SpawnEntry(448.0, 576.0, 0.0, SPAWN_ID_16, 22000, 1),
    ]


@register_quest(
    level="2.3",
    title="Arachnoid Farm",
    time_limit_ms=240000,
    start_weapon_id=1,
    unlock_perk_id=0x21,
    builder_address=0x00436820,
)
def build_2_3_arachnoid_farm(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    if ctx.player_count + 4 >= 0:
        trigger = 500
        for idx in range(ctx.player_count + 4):
            x = idx * 102.4 + 256.0
            entries.append(SpawnEntry(x, 256.0, 0.0, SPAWN_ID_10, trigger, 1))
            trigger += 500
        trigger = 10500
        for idx in range(ctx.player_count + 4):
            x = idx * 102.4 + 256.0
            entries.append(SpawnEntry(x, 768.0, 0.0, SPAWN_ID_10, trigger, 1))
            trigger += 500
    if ctx.player_count + 7 >= 0:
        trigger = 40500
        for idx in range(ctx.player_count + 7):
            x = idx * 64.0 + 256.0
            entries.append(SpawnEntry(x, 512.0, 0.0, SPAWN_ID_16, trigger, 1))
            trigger += 3500
    return entries


@register_quest(
    level="2.4",
    title="Two Fronts",
    time_limit_ms=240000,
    start_weapon_id=1,
    unlock_weapon_id=0x15,
    builder_address=0x00436ee0,
)
def build_2_4_two_fronts(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    half_w = ctx.width // 2
    edge_w = ctx.width + 64
    for wave in range(0, 40):
        trigger_a = wave * 2000 + 1000
        trigger_b = (wave * 5 + 5) * 400
        entries.append(SpawnEntry(edge_w, float(half_w), 0.0, SPAWN_ID_26, trigger_a, 1))
        entries.append(SpawnEntry(-64.0, float(half_w), 0.0, SPAWN_ID_27, trigger_b, 1))
        if wave in (10, 20):
            trigger = wave * 2000 + 2500
            entries.append(SpawnEntry(256.0, 256.0, 0.0, SPAWN_ID_10, trigger, 1))
            entries.append(SpawnEntry(768.0, 768.0, 0.0, SPAWN_ID_7, trigger, 1))
        if wave == 30:
            trigger = 62500
            entries.append(SpawnEntry(768.0, 256.0, 0.0, SPAWN_ID_10, trigger, 1))
            entries.append(SpawnEntry(256.0, 768.0, 0.0, SPAWN_ID_7, trigger, 1))
    return entries


@register_quest(
    level="2.5",
    title="Sweep Stakes",
    time_limit_ms=35000,
    start_weapon_id=6,
    unlock_perk_id=0x22,
    builder_address=0x00437810,
)
def build_2_5_sweep_stakes(ctx: QuestContext, rng: random.Random | None = None) -> list[SpawnEntry]:
    rng = rng or random.Random()
    entries: list[SpawnEntry] = []
    trigger = 2000
    step = 2000
    while step > 720:
        angle = (rng.randrange(0x264)) * 0.01
        cos_a = math.cos(angle)
        sin_a = math.sin(angle)
        radius = 0x54
        while radius < 0xFC:
            x = radius * cos_a + 512.0
            y = radius * sin_a + 512.0
            heading = math.atan2(y - 512.0, x - 512.0) - (math.pi / 2.0)
            entries.append(SpawnEntry(x, y, heading, SPAWN_ID_54, trigger, 1))
            radius += 0x2A
        trigger += max(step, 600)
        step -= 0x50
    return entries


@register_quest(
    level="2.6",
    title="Evil Zombies At Large",
    time_limit_ms=180000,
    start_weapon_id=1,
    unlock_weapon_id=0x07,
    builder_address=0x004374a0,
)
def build_2_6_evil_zombies_at_large(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    half_w = ctx.width // 2
    edge_w = ctx.width + 64
    trigger = 1500
    count = 4
    while count <= 13:
        entries.append(SpawnEntry(edge_w, float(half_w), 0.0, SPAWN_ID_65, trigger, count))
        entries.append(SpawnEntry(-64.0, float(half_w), 0.0, SPAWN_ID_65, trigger, count))
        entries.append(SpawnEntry(float(half_w), float(edge_w), 0.0, SPAWN_ID_65, trigger, count))
        entries.append(SpawnEntry(float(half_w), -64.0, 0.0, SPAWN_ID_65, trigger, count))
        trigger += 5500
        count += 1
    return entries


@register_quest(
    level="2.7",
    title="Survival Of The Fastest",
    time_limit_ms=120000,
    start_weapon_id=5,
    unlock_perk_id=0x23,
    builder_address=0x00437060,
)
def build_2_7_survival_of_the_fastest(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry | None] = [None] * 26

    def set_entry(idx: int, x: float, y: float, spawn_id: int, trigger: int, count: int) -> None:
        if idx < 0 or idx >= len(entries):
            return
        entries[idx] = SpawnEntry(x, y, 0.0, spawn_id, trigger, count)

    # Loop 1: x from 256 to <688, step 72
    trigger = 500
    idx = 0
    for x in range(0x100, 0x2B0, 0x48):
        set_entry(idx, float(x), 256.0, SPAWN_ID_16, trigger, 1)
        trigger += 900
        idx += 1

    # Loop 2: y from 256 to <688, step 72, starting at index 6
    trigger = 5900
    idx = 6
    for y in range(0x100, 0x2B0, 0x48):
        set_entry(idx, 688.0, float(y), SPAWN_ID_16, trigger, 1)
        trigger += 900
        idx += 1

    # Loop 3: x descending from 688, y=688, starting at index 12
    trigger = 11300
    idx = 12
    for x in (0x2B0, 0x268, 0x220, 0x1D8):
        set_entry(idx, float(x), 688.0, SPAWN_ID_16, trigger, 1)
        trigger += 900
        idx += 1

    # Loop 4: y descending from 688, x=400, starting at index 16
    trigger = 14900
    idx = 16
    for y in (0x2B0, 0x268, 0x220, 0x1D8):
        set_entry(idx, 400.0, float(y), SPAWN_ID_16, trigger, 1)
        trigger += 900
        idx += 1

    # Loop 5: x from 400 to <544, y=400, starting at index 20
    trigger = 18500
    idx = 20
    for x in range(400, 0x220, 0x48):
        set_entry(idx, float(x), 400.0, SPAWN_ID_16, trigger, 1)
        trigger += 900
        idx += 1

    # Final fixed entries
    set_entry(22, 128.0, 128.0, SPAWN_ID_16, 22300, 1)
    set_entry(23, 896.0, 128.0, SPAWN_ID_7, 22300, 1)
    set_entry(24, 128.0, 896.0, SPAWN_ID_7, 24300, 1)
    set_entry(25, 896.0, 896.0, SPAWN_ID_16, 24300, 1)

    return [entry for entry in entries if entry is not None]


@register_quest(
    level="2.8",
    title="Land Of Lizards",
    time_limit_ms=180000,
    start_weapon_id=1,
    unlock_weapon_id=0x04,
    builder_address=0x00437ba0,
)
def build_2_8_land_of_lizards(ctx: QuestContext) -> list[SpawnEntry]:
    return [
        SpawnEntry(256.0, 256.0, 0.0, SPAWN_ID_14, 2000, 1),
        SpawnEntry(768.0, 256.0, 0.0, SPAWN_ID_14, 12000, 1),
        SpawnEntry(256.0, 768.0, 0.0, SPAWN_ID_14, 22000, 1),
        SpawnEntry(768.0, 768.0, 0.0, SPAWN_ID_14, 32000, 1),
    ]


@register_quest(
    level="2.9",
    title="Ghost Patrols",
    time_limit_ms=180000,
    start_weapon_id=1,
    unlock_perk_id=0x24,
    builder_address=0x00436200,
)
def build_2_9_ghost_patrols(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    half_w = ctx.width // 2
    entries.append(SpawnEntry(ctx.width + 128.0, float(half_w), 0.0, SPAWN_ID_43, 1500, 2))
    trigger = 2500
    for i in range(12):
        x = -128.0 if i % 2 == 0 else 1152.0
        entries.append(SpawnEntry(x, float(half_w), 0.0, SPAWN_ID_25, trigger, 1))
        trigger += 2500
    loop_count = 12
    entries.append(SpawnEntry(-264.0, float(half_w), 0.0, SPAWN_ID_43, (loop_count - 1) * 2500, 1))
    special_trigger = (5 * loop_count + 15) * 500
    entries.append(SpawnEntry(-128.0, float(half_w), 0.0, SPAWN_ID_24, special_trigger, 1))
    return entries


@register_quest(
    level="2.10",
    title="Spideroids",
    time_limit_ms=360000,
    start_weapon_id=1,
    unlock_weapon_id=0x0B,
    builder_address=0x004373c0,
)
def build_2_10_spideroids(ctx: QuestContext, full_version: bool = True) -> list[SpawnEntry]:
    entries = [
        SpawnEntry(1088.0, 512.0, 0.0, SPAWN_ID_1, 1000, 1),
        SpawnEntry(-64.0, 512.0, 0.0, SPAWN_ID_1, 3000, 1),
        SpawnEntry(1088.0, 256.0, 0.0, SPAWN_ID_1, 6000, 1),
    ]
    if full_version:
        entries.append(SpawnEntry(1088.0, 762.0, 0.0, SPAWN_ID_1, 9000, 1))
        entries.append(SpawnEntry(512.0, 1088.0, 0.0, SPAWN_ID_1, 9000, 1))
    if ctx.player_count >= 2 or full_version:
        entries.append(SpawnEntry(-64.0, 762.0, 0.0, SPAWN_ID_1, 9000, 1))
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
