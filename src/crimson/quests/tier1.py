from __future__ import annotations

import math
import random

from .types import QuestContext, SpawnEntry

SPAWN_ID_8 = 0x08
SPAWN_ID_9 = 0x09
SPAWN_ID_18 = 0x12
SPAWN_ID_26 = 0x1A
SPAWN_ID_29 = 0x1D
SPAWN_ID_30 = 0x1E
SPAWN_ID_31 = 0x1F
SPAWN_ID_38 = 0x26
SPAWN_ID_41 = 0x29
SPAWN_ID_54 = 0x36
SPAWN_ID_58 = 0x3A
SPAWN_ID_61 = 0x3D
SPAWN_ID_64 = 0x40


def build_1_1_land_hostile(ctx: QuestContext) -> list[SpawnEntry]:
    half_w = ctx.width // 2
    edge_h = ctx.height + 64
    return [
        SpawnEntry(half_w, edge_h, 0.0, SPAWN_ID_38, 500, 1),
        SpawnEntry(-64.0, ctx.height + 64.0, 0.0, SPAWN_ID_38, 2500, 2),
        SpawnEntry(-64.0, -64.0, 0.0, SPAWN_ID_38, 6500, 3),
        SpawnEntry(ctx.width + 64.0, -64.0, 0.0, SPAWN_ID_38, 11500, 4),
    ]


def build_1_2_minor_alien_breach(ctx: QuestContext) -> list[SpawnEntry]:
    half_w = ctx.width // 2
    half_h = ctx.height // 2
    edge_w = ctx.width + 64
    entries = [
        SpawnEntry(256.0, 256.0, 0.0, SPAWN_ID_38, 1000, 2),
        SpawnEntry(256.0, 128.0, 0.0, SPAWN_ID_38, 1700, 2),
    ]
    for i in range(2, 18):
        trigger = (i * 5 - 10) * 720
        entries.append(SpawnEntry(edge_w, float(half_h), 0.0, SPAWN_ID_38, trigger, 1))
        if i > 6:
            entries.append(
                SpawnEntry(edge_w, float(half_h - 256), 0.0, SPAWN_ID_38, trigger, 1)
            )
        if i == 13:
            entries.append(
                SpawnEntry(float(half_w), ctx.height + 64.0, 0.0, SPAWN_ID_41, 39600, 1)
            )
        if i > 10:
            entries.append(
                SpawnEntry(-64.0, float(half_h + 256), 0.0, SPAWN_ID_38, trigger, 1)
            )
    return entries


def build_1_3_target_practice(
    ctx: QuestContext, rng: random.Random | None = None
) -> list[SpawnEntry]:
    rng = rng or random.Random()
    entries: list[SpawnEntry] = []
    trigger = 2000
    step = 2000
    while True:
        angle = rng.randrange(0x264) * 0.01
        radius = (rng.randrange(8) + 2) * 0x20
        x = math.cos(angle) * radius + 512.0
        y = math.sin(angle) * radius + 512.0
        heading = math.atan2(y - 512.0, x - 512.0) - (math.pi / 2.0)
        entries.append(SpawnEntry(x, y, heading, SPAWN_ID_54, trigger, 1))
        trigger += max(step, 1100)
        step -= 50
        if step <= 500:
            break
    return entries


def build_1_4_frontline_assault(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    half_w = ctx.width // 2
    edge_w = ctx.width + 64
    edge_h = ctx.height + 64
    step = 2500
    for i in range(2, 22):
        if i < 5:
            spawn_id = SPAWN_ID_38
        elif i < 10:
            spawn_id = SPAWN_ID_26
        else:
            spawn_id = SPAWN_ID_38
        trigger = i * step - 5000
        entries.append(SpawnEntry(float(half_w), edge_h, 0.0, spawn_id, trigger, 1))
        if i > 4:
            entries.append(SpawnEntry(-64.0, -64.0, 0.0, SPAWN_ID_38, trigger, 1))
        if i > 10:
            entries.append(SpawnEntry(edge_w, -64.0, 0.0, SPAWN_ID_38, trigger, 1))
        if i == 10:
            burst_trigger = (step * 5 - 2500) * 2
            entries.append(SpawnEntry(edge_w, float(half_w), 0.0, SPAWN_ID_41, burst_trigger, 1))
            entries.append(SpawnEntry(-64.0, float(half_w), 0.0, SPAWN_ID_41, burst_trigger, 1))
        step = max(step - 50, 1800)
    return entries


def build_1_5_alien_dens(ctx: QuestContext) -> list[SpawnEntry]:
    return [
        SpawnEntry(256.0, 256.0, 0.0, SPAWN_ID_8, 1500, 1),
        SpawnEntry(768.0, 768.0, 0.0, SPAWN_ID_8, 1500, 1),
        SpawnEntry(512.0, 512.0, 0.0, SPAWN_ID_8, 23500, ctx.player_count),
        SpawnEntry(256.0, 768.0, 0.0, SPAWN_ID_8, 38500, 1),
        SpawnEntry(768.0, 256.0, 0.0, SPAWN_ID_8, 38500, 1),
    ]


def build_1_6_the_random_factor(
    ctx: QuestContext, rng: random.Random | None = None
) -> list[SpawnEntry]:
    rng = rng or random.Random()
    entries: list[SpawnEntry] = []
    half_h = ctx.height // 2
    edge_w = ctx.width + 64
    trigger = 1500
    while trigger < 101500:
        entries.append(
            SpawnEntry(edge_w, float(half_h), 0.0, SPAWN_ID_29, trigger, ctx.player_count * 2 + 4)
        )
        entries.append(
            SpawnEntry(-64.0, float(half_h), 0.0, SPAWN_ID_29, trigger + 200, 6)
        )
        if rng.randrange(5) == 3:
            entries.append(
                SpawnEntry(
                    float(ctx.width // 2),
                    ctx.height + 64.0,
                    0.0,
                    SPAWN_ID_41,
                    trigger,
                    ctx.player_count,
                )
            )
        trigger += 10000
    return entries


def build_1_7_spider_wave_syndrome(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    trigger = 1500
    while trigger < 100500:
        entries.append(
            SpawnEntry(-64.0, float(ctx.height // 2), 0.0, SPAWN_ID_64, trigger, ctx.player_count * 2 + 6)
        )
        trigger += 5500
    return entries


def build_1_8_alien_squads(ctx: QuestContext) -> list[SpawnEntry]:
    entries = [
        SpawnEntry(-256.0, 256.0, 0.0, SPAWN_ID_18, 1500, 1),
        SpawnEntry(-256.0, 768.0, 0.0, SPAWN_ID_18, 2500, 1),
        SpawnEntry(768.0, -256.0, 0.0, SPAWN_ID_18, 5500, 1),
        SpawnEntry(768.0, 1280.0, 0.0, SPAWN_ID_18, 8500, 1),
        SpawnEntry(1280.0, 1280.0, 0.0, SPAWN_ID_18, 14500, 1),
        SpawnEntry(1280.0, 768.0, 0.0, SPAWN_ID_18, 18500, 1),
        SpawnEntry(-256.0, 256.0, 0.0, SPAWN_ID_18, 25000, 1),
        SpawnEntry(-256.0, 768.0, 0.0, SPAWN_ID_18, 30000, 1),
    ]
    trigger = 36200
    while trigger < 83000:
        entries.append(
            SpawnEntry(-64.0, -64.0, 0.0, SPAWN_ID_38, trigger - 400, 1)
        )
        entries.append(
            SpawnEntry(ctx.width + 64.0, ctx.height + 64.0, 0.0, SPAWN_ID_38, trigger, 1)
        )
        trigger += 1800
    return entries


def build_1_9_nesting_grounds(ctx: QuestContext) -> list[SpawnEntry]:
    entries = [
        SpawnEntry(float(ctx.width // 2), ctx.height + 64.0, 0.0, SPAWN_ID_29, 1500, ctx.player_count * 2 + 6),
        SpawnEntry(256.0, 256.0, 0.0, SPAWN_ID_9, 8000, 1),
        SpawnEntry(512.0, 512.0, 0.0, SPAWN_ID_9, 13000, 1),
        SpawnEntry(768.0, 768.0, 0.0, SPAWN_ID_9, 18000, 1),
        SpawnEntry(float(ctx.width // 2), ctx.height + 64.0, 0.0, SPAWN_ID_29, 25000, ctx.player_count * 2 + 6),
        SpawnEntry(float(ctx.width // 2), ctx.height + 64.0, 0.0, SPAWN_ID_29, 39000, ctx.player_count * 3 + 3),
        SpawnEntry(384.0, 512.0, 0.0, SPAWN_ID_9, 41100, 1),
        SpawnEntry(640.0, 512.0, 0.0, SPAWN_ID_9, 42100, 1),
        SpawnEntry(512.0, 640.0, 0.0, SPAWN_ID_9, 43100, 1),
        SpawnEntry(512.0, 512.0, 0.0, SPAWN_ID_8, 44100, 1),
        SpawnEntry(float(ctx.width // 2), ctx.height + 64.0, 0.0, SPAWN_ID_30, 50000, ctx.player_count * 2 + 5),
        SpawnEntry(float(ctx.width // 2), ctx.height + 64.0, 0.0, SPAWN_ID_31, 55000, ctx.player_count * 2 + 2),
    ]
    return entries


def build_1_10_8_legged_terror(ctx: QuestContext) -> list[SpawnEntry]:
    entries = [
        SpawnEntry(float(ctx.width - 256), float(ctx.width // 2), 0.0, SPAWN_ID_58, 1000, 1)
    ]
    trigger = 6000
    while trigger < 36800:
        entries.append(
            SpawnEntry(-25.0, -25.0, 0.0, SPAWN_ID_61, trigger, ctx.player_count)
        )
        entries.append(
            SpawnEntry(ctx.width + 25.0, -25.0, 0.0, SPAWN_ID_61, trigger, 1)
        )
        entries.append(
            SpawnEntry(-25.0, ctx.height + 25.0, 0.0, SPAWN_ID_61, trigger, ctx.player_count)
        )
        entries.append(
            SpawnEntry(ctx.width + 25.0, ctx.height + 25.0, 0.0, SPAWN_ID_61, trigger, 1)
        )
        trigger += 2200
    return entries


TIER1_BUILDERS = {
    "1.1": build_1_1_land_hostile,
    "1.2": build_1_2_minor_alien_breach,
    "1.3": build_1_3_target_practice,
    "1.4": build_1_4_frontline_assault,
    "1.5": build_1_5_alien_dens,
    "1.6": build_1_6_the_random_factor,
    "1.7": build_1_7_spider_wave_syndrome,
    "1.8": build_1_8_alien_squads,
    "1.9": build_1_9_nesting_grounds,
    "1.10": build_1_10_8_legged_terror,
}

__all__ = [
    "QuestContext",
    "SpawnEntry",
    "TIER1_BUILDERS",
    "build_1_1_land_hostile",
    "build_1_2_minor_alien_breach",
    "build_1_3_target_practice",
    "build_1_4_frontline_assault",
    "build_1_5_alien_dens",
    "build_1_6_the_random_factor",
    "build_1_7_spider_wave_syndrome",
    "build_1_8_alien_squads",
    "build_1_9_nesting_grounds",
    "build_1_10_8_legged_terror",
]
