from __future__ import annotations

import math
import random

from .types import QuestContext, QuestDefinition, SpawnEntry

SPAWN_ID_0 = 0x00
SPAWN_ID_7 = 0x07
SPAWN_ID_12 = 0x0C
SPAWN_ID_13 = 0x0D
SPAWN_ID_17 = 0x11
SPAWN_ID_26 = 0x1A
SPAWN_ID_27 = 0x1B
SPAWN_ID_28 = 0x1C
SPAWN_ID_33 = 0x21
SPAWN_ID_34 = 0x22
SPAWN_ID_35 = 0x23
SPAWN_ID_43 = 0x2B
SPAWN_ID_46 = 0x2E
SPAWN_ID_49 = 0x31
SPAWN_ID_56 = 0x38
SPAWN_ID_64 = 0x40


def build_3_1_the_blighting(ctx: QuestContext) -> list[SpawnEntry]:
    half_w = ctx.width // 2
    entries = [
        SpawnEntry(ctx.width + 128.0, float(half_w), 0.0, SPAWN_ID_43, 1500, 2),
        SpawnEntry(-128.0, float(half_w), 0.0, SPAWN_ID_43, 1500, 2),
        SpawnEntry(896.0, 128.0, 0.0, SPAWN_ID_7, 2000, 1),
        SpawnEntry(128.0, 128.0, 0.0, SPAWN_ID_7, 2000, 1),
        SpawnEntry(128.0, 896.0, 0.0, SPAWN_ID_7, 2000, 1),
        SpawnEntry(896.0, 896.0, 0.0, SPAWN_ID_7, 2000, 1),
    ]

    trigger = 4000
    for wave in range(8):
        if wave in (2, 4):
            entries.append(SpawnEntry(-128.0, float(half_w), 0.0, SPAWN_ID_43, trigger, 4))
        if wave in (3, 5):
            entries.append(SpawnEntry(1152.0, float(half_w), 0.0, SPAWN_ID_43, trigger, 4))
        spawn_id = SPAWN_ID_26 if wave % 2 == 0 else SPAWN_ID_28
        edge = wave % 5
        if edge == 0:
            entries.append(
                SpawnEntry(ctx.width + 64.0, float(half_w), 0.0, spawn_id, trigger, 12)
            )
            trigger += 15000
        elif edge == 1:
            entries.append(SpawnEntry(-64.0, float(half_w), 0.0, spawn_id, trigger, 12))
            trigger += 15000
        elif edge == 2:
            entries.append(
                SpawnEntry(float(half_w), ctx.width + 64.0, 0.0, spawn_id, trigger, 12)
            )
            trigger += 15000
        elif edge == 3:
            entries.append(
                SpawnEntry(float(half_w), -64.0, 0.0, spawn_id, trigger, 12)
            )
            trigger += 15000
        trigger += 1000
    return entries


def build_3_2_lizard_kings(ctx: QuestContext) -> list[SpawnEntry]:
    entries = [
        SpawnEntry(1152.0, 512.0, 0.0, SPAWN_ID_17, 1500, 1),
        SpawnEntry(-128.0, 512.0, 0.0, SPAWN_ID_17, 1500, 1),
        SpawnEntry(1152.0, 896.0, 0.0, SPAWN_ID_17, 1500, 1),
    ]
    trigger = 1500
    for idx in range(28):
        angle = idx * 0.34906587
        x = math.cos(angle) * 256.0 + 512.0
        y = math.sin(angle) * 256.0 + 512.0
        heading = -angle
        entries.append(SpawnEntry(x, y, heading, SPAWN_ID_49, trigger, 1))
        trigger += 900
    return entries


def build_3_3_the_killing(
    ctx: QuestContext, rng: random.Random | None = None
) -> list[SpawnEntry]:
    rng = rng or random.Random()
    entries: list[SpawnEntry] = []
    trigger = 2000
    for wave in range(10):
        rng.randrange(0x8000)
        rng.randrange(0x8000)
        spawn_cycle = wave % 3
        if spawn_cycle == 0:
            spawn_id = SPAWN_ID_26
        elif spawn_cycle == 1:
            spawn_id = SPAWN_ID_27
        else:
            spawn_id = SPAWN_ID_28

        edge = wave % 5
        if edge == 0:
            entries.append(
                SpawnEntry(ctx.width + 64.0, ctx.width / 2, 0.0, spawn_id, trigger, 12)
            )
        elif edge == 1:
            entries.append(SpawnEntry(-64.0, ctx.width / 2, 0.0, spawn_id, trigger, 12))
        elif edge == 2:
            entries.append(
                SpawnEntry(ctx.width / 2, ctx.width + 64.0, 0.0, spawn_id, trigger, 12)
            )
        elif edge == 3:
            entries.append(SpawnEntry(ctx.width / 2, -64.0, 0.0, spawn_id, trigger, 12))
        else:
            for offset in (0, 1000, 2000):
                x = rng.randrange(0x300) + 0x80
                y = rng.randrange(0x300) + 0x80
                entries.append(SpawnEntry(float(x), float(y), 0.0, SPAWN_ID_7, trigger + offset, 3))

        trigger += 6000
    return entries


def build_3_4_hidden_evil(ctx: QuestContext) -> list[SpawnEntry]:
    half_w = ctx.width // 2
    edge_h = ctx.height + 64
    return [
        SpawnEntry(float(half_w), float(edge_h), 0.0, SPAWN_ID_33, 500, 50),
        SpawnEntry(float(half_w), float(edge_h), 0.0, SPAWN_ID_34, 15000, 30),
        SpawnEntry(float(half_w), float(edge_h), 0.0, SPAWN_ID_35, 25000, 20),
        SpawnEntry(float(half_w), float(edge_h), 0.0, SPAWN_ID_35, 30000, 30),
        SpawnEntry(float(half_w), float(edge_h), 0.0, SPAWN_ID_34, 35000, 30),
    ]


def build_3_5_surrounded_by_reptiles(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    trigger = 1000
    offset = 0
    while trigger < 5000:
        y = offset * 0.2 + 256.0
        entries.append(SpawnEntry(256.0, y, 0.0, SPAWN_ID_13, trigger, 1))
        entries.append(SpawnEntry(768.0, y, 0.0, SPAWN_ID_13, trigger, 1))
        trigger += 800
        offset += 0x200

    trigger = 8000
    offset = 0
    while trigger < 12000:
        x = offset * 0.2 + 256.0
        entries.append(SpawnEntry(x, 256.0, 0.0, SPAWN_ID_13, trigger, 1))
        entries.append(SpawnEntry(x, 768.0, 0.0, SPAWN_ID_13, trigger, 1))
        trigger += 800
        offset += 0x200
    return entries


def build_3_6_the_lizquidation(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    half_w = ctx.width // 2
    trigger = 1500
    for wave in range(10):
        count = wave + 6
        entries.append(SpawnEntry(ctx.width + 64.0, float(half_w), 0.0, SPAWN_ID_46, trigger, count))
        entries.append(SpawnEntry(-64.0, float(half_w), 0.0, SPAWN_ID_46, trigger, count))
        if wave == 4:
            entries.append(
                SpawnEntry(ctx.width + 128.0, float(half_w), 0.0, SPAWN_ID_43, 1500, 2)
            )
        trigger += 8000
    return entries


def build_3_7_spiders_inc(ctx: QuestContext) -> list[SpawnEntry]:
    half_w = ctx.width // 2
    entries = [
        SpawnEntry(float(half_w), ctx.width + 64.0, 0.0, SPAWN_ID_56, 500, 1),
        SpawnEntry(float(half_w + 64), ctx.width + 64.0, 0.0, SPAWN_ID_56, 500, 1),
        SpawnEntry(float(half_w), -64.0, 0.0, SPAWN_ID_64, 500, 4),
    ]

    trigger = 17000
    step_count = 0
    while trigger < 107000:
        count = step_count // 2 + 3
        entries.append(SpawnEntry(float(half_w), ctx.width + 64.0, 0.0, SPAWN_ID_56, trigger, count))
        entries.append(SpawnEntry(float(half_w), -64.0, 0.0, SPAWN_ID_56, trigger, count))
        trigger += 6000
        step_count += 1
    return entries


def build_3_8_lizard_raze(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    half_w = ctx.width // 2
    trigger = 1500
    while trigger < 91500:
        entries.append(SpawnEntry(ctx.width + 64.0, float(half_w), 0.0, SPAWN_ID_46, trigger, 6))
        entries.append(SpawnEntry(-64.0, float(half_w), 0.0, SPAWN_ID_46, trigger, 6))
        trigger += 6000
    entries.extend(
        [
            SpawnEntry(128.0, 256.0, 0.0, SPAWN_ID_12, 10000, 1),
            SpawnEntry(128.0, 384.0, 0.0, SPAWN_ID_12, 10000, 1),
            SpawnEntry(128.0, 512.0, 0.0, SPAWN_ID_12, 10000, 1),
        ]
    )
    return entries


def build_3_9_deja_vu(ctx: QuestContext, rng: random.Random | None = None) -> list[SpawnEntry]:
    rng = rng or random.Random()
    entries: list[SpawnEntry] = []
    trigger = 2000
    step = 2000
    while step > 560:
        angle = (rng.randrange(0x264)) * 0.01
        cos_a = math.cos(angle)
        sin_a = math.sin(angle)
        radius = 0x54
        while radius < 0xFC:
            x = radius * cos_a + 512.0
            y = radius * sin_a + 512.0
            entries.append(SpawnEntry(x, y, 0.0, SPAWN_ID_13, trigger, 1))
            radius += 0x2A
        trigger += step
        step -= 0x50
    return entries


def build_3_10_zombie_masters(ctx: QuestContext) -> list[SpawnEntry]:
    return [
        SpawnEntry(256.0, 256.0, 0.0, SPAWN_ID_0, 1000, ctx.player_count),
        SpawnEntry(512.0, 256.0, 0.0, SPAWN_ID_0, 6000, 1),
        SpawnEntry(768.0, 256.0, 0.0, SPAWN_ID_0, 14000, ctx.player_count),
        SpawnEntry(768.0, 768.0, 0.0, SPAWN_ID_0, 18000, 1),
    ]


QUESTS = [
    QuestDefinition("3.1", "The Blighting", build_3_1_the_blighting),
    QuestDefinition("3.2", "Lizard Kings", build_3_2_lizard_kings),
    QuestDefinition("3.3", "The Killing", build_3_3_the_killing),
    QuestDefinition("3.4", "Hidden Evil", build_3_4_hidden_evil),
    QuestDefinition("3.5", "Surrounded By Reptiles", build_3_5_surrounded_by_reptiles),
    QuestDefinition("3.6", "The Lizquidation", build_3_6_the_lizquidation),
    QuestDefinition("3.7", "Spiders Inc.", build_3_7_spiders_inc),
    QuestDefinition("3.8", "Lizard Raze", build_3_8_lizard_raze),
    QuestDefinition("3.9", "Deja vu", build_3_9_deja_vu),
    QuestDefinition("3.10", "Zombie Masters", build_3_10_zombie_masters),
]

TIER3_BUILDERS = {quest.level: quest.builder for quest in QUESTS}
TIER3_TITLES = {quest.level: quest.title for quest in QUESTS}

__all__ = [
    "QuestContext",
    "QuestDefinition",
    "SpawnEntry",
    "QUESTS",
    "TIER3_BUILDERS",
    "TIER3_TITLES",
    "build_3_1_the_blighting",
    "build_3_2_lizard_kings",
    "build_3_3_the_killing",
    "build_3_4_hidden_evil",
    "build_3_5_surrounded_by_reptiles",
    "build_3_6_the_lizquidation",
    "build_3_7_spiders_inc",
    "build_3_8_lizard_raze",
    "build_3_9_deja_vu",
    "build_3_10_zombie_masters",
]
