from __future__ import annotations

import math

from ..perks import PerkId
from .helpers import center_point, ring_points
from .registry import register_quest
from .types import QuestContext, SpawnEntry

SPAWN_ID_0 = 0x00
SPAWN_ID_1 = 0x01
SPAWN_ID_3 = 0x03
SPAWN_ID_4 = 0x04
SPAWN_ID_5 = 0x05
SPAWN_ID_6 = 0x06
SPAWN_ID_9 = 0x09
SPAWN_ID_10 = 0x0A
SPAWN_ID_11 = 0x0B
SPAWN_ID_14 = 0x0E
SPAWN_ID_15 = 0x0F
SPAWN_ID_18 = 0x12
SPAWN_ID_19 = 0x13
SPAWN_ID_21 = 0x15
SPAWN_ID_22 = 0x16
SPAWN_ID_23 = 0x17
SPAWN_ID_28 = 0x1C
SPAWN_ID_37 = 0x25
SPAWN_ID_39 = 0x27
SPAWN_ID_41 = 0x29
SPAWN_ID_58 = 0x3A
SPAWN_ID_60 = 0x3C
SPAWN_ID_64 = 0x40
SPAWN_ID_65 = 0x41
SPAWN_ID_66 = 0x42
SPAWN_ID_67 = 0x43

@register_quest(
    level="5.1",
    title="The Beating",
    time_limit_ms=480000,
    start_weapon_id=1,
    unlock_weapon_id=0x1F,
    builder_address=0x00435610,
)
def build_5_1_the_beating(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = [
        SpawnEntry(256.0, 256.0, 0.0, SPAWN_ID_39, 500, 1),
        SpawnEntry(ctx.width + 32.0, float(ctx.height // 2), 0.0, SPAWN_ID_41, 8000, 3),
    ]

    trigger = 10000
    x_offset = 0x40
    for _ in range(8):
        entries.append(
            SpawnEntry(float(ctx.width + x_offset), float(ctx.height // 2), 0.0, SPAWN_ID_37, trigger, 8)
        )
        trigger += 100
        x_offset += 0x20

    entries.append(
        SpawnEntry(-32.0, float(ctx.height // 2), 0.0, SPAWN_ID_41, 18000, 3)
    )

    trigger = 20000
    x = -64
    for _ in range(8):
        entries.append(SpawnEntry(float(x), float(ctx.height // 2), 0.0, SPAWN_ID_37, trigger, 8))
        trigger += 100
        x -= 32

    trigger = 40000
    y = -64
    for _ in range(6):
        entries.append(SpawnEntry(float(ctx.width // 2), float(y), 0.0, SPAWN_ID_15, trigger, 4))
        trigger += 100
        y -= 42

    trigger = 40000
    y = ctx.width + 0x2C
    for _ in range(6):
        entries.append(SpawnEntry(float(ctx.width // 2), float(y), 0.0, SPAWN_ID_18, trigger, 2))
        trigger += 100
        y += 0x20

    return entries

@register_quest(
    level="5.2",
    title="The Spanking Of The Dead",
    time_limit_ms=480000,
    start_weapon_id=1,
    unlock_perk_id=PerkId.DEATH_CLOCK,
    builder_address=0x004358a0,
)
def build_5_2_the_spanking_of_the_dead(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = [
        SpawnEntry(256.0, 512.0, 0.0, SPAWN_ID_39, 500, 1),
        SpawnEntry(768.0, 512.0, 0.0, SPAWN_ID_39, 500, 1),
    ]

    trigger = 5000
    step_index = 0
    while trigger < 0xA988:
        angle = step_index * 0.33333334
        radius = 512.0 - step_index * 3.8
        x = math.cos(angle) * radius + 512.0
        y = math.sin(angle) * radius + 512.0
        entries.append(SpawnEntry(x, y, angle, SPAWN_ID_65, trigger, 1))
        trigger += 300
        step_index += 1

    offset = step_index * 300
    entries.append(SpawnEntry(1280.0, 512.0, 0.0, SPAWN_ID_66, offset + 10000, 16))
    entries.append(SpawnEntry(-256.0, 512.0, 0.0, SPAWN_ID_66, offset + 20000, 16))
    return entries

@register_quest(
    level="5.3",
    title="The Fortress",
    time_limit_ms=480000,
    start_weapon_id=1,
    unlock_perk_id=PerkId.MY_FAVOURITE_WEAPON,
    builder_address=0x004352d0,
)
def build_5_3_the_fortress(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = [
        SpawnEntry(-50.0, float(ctx.height // 2), 0.0, SPAWN_ID_64, 100, 6),
    ]

    trigger = 1100
    y_seed = 0x200
    while trigger < 0x14B4:
        y = y_seed * 0.125 + 256.0
        entries.append(SpawnEntry(768.0, float(y), 0.0, SPAWN_ID_9, trigger, 1))
        trigger += 600
        y_seed += 0x200

    entry_count = 8
    x_seed = 0x180
    while x_seed < 0x901:
        trigger = entry_count * 600 + 0x157C
        for row in range(1, 7):
            if row != 1 or x_seed not in (0x480, 0x600):
                x = x_seed * 0.16666667 + 256.0
                y = 512.0 - (row * 0x180) * 0.16666667
                entries.append(SpawnEntry(float(x), float(y), 0.0, SPAWN_ID_10, trigger, 1))
                trigger += 600
                entry_count += 1
        x_seed += 0x180

    return entries

@register_quest(
    level="5.4",
    title="The Gang Wars",
    time_limit_ms=480000,
    start_weapon_id=1,
    unlock_weapon_id=0x1E,
    builder_address=0x00435120,
)
def build_5_4_the_gang_wars(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = [
        SpawnEntry(-150.0, float(ctx.height // 2), 0.0, SPAWN_ID_18, 100, 1),
        SpawnEntry(1174.0, float(ctx.height // 2), 0.0, SPAWN_ID_18, 2500, 1),
    ]

    trigger = 5500
    for _ in range(10):
        entries.append(SpawnEntry(1174.0, float(ctx.height // 2), 0.0, SPAWN_ID_18, trigger, 2))
        trigger += 4000

    entries.append(SpawnEntry(512.0, 1152.0, 0.0, SPAWN_ID_19, 50500, 1))

    trigger = 59500
    while trigger < 0x184AC:
        entries.append(SpawnEntry(-150.0, float(ctx.height // 2), 0.0, SPAWN_ID_18, trigger, 2))
        trigger += 4000

    entries.append(SpawnEntry(512.0, 1152.0, 0.0, SPAWN_ID_19, 107500, 3))
    return entries

@register_quest(
    level="5.5",
    title="Knee-deep in the Dead",
    time_limit_ms=480000,
    start_weapon_id=1,
    unlock_perk_id=PerkId.BANDAGE,
    builder_address=0x00434f00,
)
def build_5_5_knee_deep_in_the_dead(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = [
        SpawnEntry(-50.0, float(ctx.height * 0.5), 0.0, SPAWN_ID_67, 100, 1),
    ]

    trigger = 500
    wave = 0
    while trigger < 0x178F4:
        if wave % 8 == 0:
            entries.append(
                SpawnEntry(-50.0, float(ctx.height * 0.5), 0.0, SPAWN_ID_67, trigger - 2, 1)
            )
        count = 2 if wave > 0x20 else 1
        entries.append(
            SpawnEntry(-50.0, float(ctx.height * 0.5), 0.0, SPAWN_ID_65, trigger, count)
        )
        if trigger > 0x30D4:
            entries.append(
                SpawnEntry(-50.0, float(ctx.height * 0.5 + 158.0), 0.0, SPAWN_ID_65, trigger + 500, 1)
            )
        if trigger > 0x5FB4:
            entries.append(
                SpawnEntry(-50.0, float(ctx.height * 0.5 - 158.0), 0.0, SPAWN_ID_65, trigger + 1000, 1)
            )
        if trigger > 0x8E94:
            entries.append(
                SpawnEntry(-50.0, float(ctx.height * 0.5 - 258.0), 0.0, SPAWN_ID_66, trigger + 0x514, 1)
            )
        if trigger > 0xBD74:
            entries.append(
                SpawnEntry(-50.0, float(ctx.height * 0.5 + 258.0), 0.0, SPAWN_ID_66, trigger + 300, 1)
            )
        trigger += 0x5DC
        wave += 1

    return entries

@register_quest(
    level="5.6",
    title="Cross Fire",
    time_limit_ms=480000,
    start_weapon_id=1,
    unlock_perk_id=PerkId.ANGRY_RELOADER,
    builder_address=0x00435480,
)
def build_5_6_cross_fire(ctx: QuestContext) -> list[SpawnEntry]:
    return [
        SpawnEntry(1074.0, float(ctx.height * 0.5), 0.0, SPAWN_ID_64, 100, 6),
        SpawnEntry(-40.0, 512.0, 0.0, SPAWN_ID_60, 5500, 4),
        SpawnEntry(-40.0, 512.0, 0.0, SPAWN_ID_60, 15500, 6),
        SpawnEntry(512.0, 512.0, 0.0, SPAWN_ID_1, 18500, 2),
        SpawnEntry(-100.0, 512.0, 0.0, SPAWN_ID_60, 25500, 8),
        SpawnEntry(512.0, 1152.0, 0.0, SPAWN_ID_64, 26000, 6),
        SpawnEntry(512.0, -128.0, 0.0, SPAWN_ID_64, 26000, 6),
    ]

@register_quest(
    level="5.7",
    title="Army of Three",
    time_limit_ms=480000,
    start_weapon_id=1,
    builder_address=0x00434ca0,
)
def build_5_7_army_of_three(ctx: QuestContext) -> list[SpawnEntry]:
    return [
        SpawnEntry(-64.0, 256.0, 0.0, SPAWN_ID_21, 500, 1),
        SpawnEntry(-64.0, 512.0, 0.0, SPAWN_ID_21, 5500, 1),
        SpawnEntry(-64.0, 768.0, 0.0, SPAWN_ID_21, 15000, 1),
        SpawnEntry(-64.0, 768.0, 0.0, SPAWN_ID_23, 19500, 1),
        SpawnEntry(-64.0, 512.0, 0.0, SPAWN_ID_23, 22500, 1),
        SpawnEntry(-64.0, 256.0, 0.0, SPAWN_ID_23, 26500, 1),
        SpawnEntry(-64.0, 256.0, 0.0, SPAWN_ID_22, 35500, 1),
        SpawnEntry(-64.0, 512.0, 0.0, SPAWN_ID_22, 39500, 1),
        SpawnEntry(-64.0, 768.0, 0.0, SPAWN_ID_22, 42500, 1),
        SpawnEntry(512.0, 1152.0, 0.0, SPAWN_ID_21, 52500, 3),
        SpawnEntry(512.0, -256.0, 0.0, SPAWN_ID_23, 56500, 3),
    ]

@register_quest(
    level="5.8",
    title="Monster Blues",
    time_limit_ms=480000,
    start_weapon_id=1,
    unlock_perk_id=PerkId.ION_GUN_MASTER,
    builder_address=0x00434860,
)
def build_5_8_monster_blues(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = [
        SpawnEntry(-50.0, float(ctx.height * 0.5), 0.0, SPAWN_ID_4, 500, 10),
        SpawnEntry(1074.0, float(ctx.height * 0.5), 0.0, SPAWN_ID_6, 7500, 10),
        SpawnEntry(512.0, 1088.0, 0.0, SPAWN_ID_3, 17500, 12),
        SpawnEntry(512.0, -64.0, 0.0, SPAWN_ID_3, 17500, 12),
    ]

    trigger = 27500
    for idx in range(0x40):
        if idx % 4 == 0:
            spawn_id = SPAWN_ID_6
        elif idx % 4 == 1:
            spawn_id = SPAWN_ID_3
        else:
            spawn_id = SPAWN_ID_5
        count = idx // 8 + 2
        entries.append(SpawnEntry(-64.0, 512.0, 0.0, spawn_id, trigger, count))
        trigger += 900
    return entries

@register_quest(
    level="5.9",
    title="Nagolipoli",
    time_limit_ms=480000,
    start_weapon_id=1,
    unlock_perk_id=PerkId.STATIONARY_RELOADER,
    builder_address=0x00434480,
)
def build_5_9_nagolipoli(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []

    center_x, center_y = center_point(ctx.width, ctx.height)
    for x, y, angle in ring_points(
        center_x, center_y, 128.0, 8, step=0.7853982
    ):
        entries.append(SpawnEntry(x, y, angle, SPAWN_ID_64, 2000, 1))

    for x, y, angle in ring_points(
        center_x, center_y, 178.0, 12, step=0.5235988
    ):
        entries.append(SpawnEntry(x, y, angle, SPAWN_ID_64, 8000, 1))

    trigger = 13000
    wave = 0
    while trigger < 0x96C8:
        count = wave // 8 + 1
        entries.extend(
            [
                SpawnEntry(-64.0, -64.0, 1.0471976, SPAWN_ID_28, trigger, count),
                SpawnEntry(1088.0, -64.0, -1.0471976, SPAWN_ID_28, trigger, count),
                SpawnEntry(-64.0, 1088.0, -1.0471976, SPAWN_ID_28, trigger, count),
                SpawnEntry(1088.0, 1088.0, 3.926991, SPAWN_ID_28, trigger, count),
            ]
        )
        trigger += 800
        wave += 1

    last_wave = max(wave - 1, 0)
    base_left = (last_wave + 0x97 + wave * 4) * 0xA0
    for idx in range(6):
        y = idx * 85.333336 + 256.0
        entries.append(SpawnEntry(64.0, y, 0.0, SPAWN_ID_10, base_left, 1))
        base_left += 100

    base_right = wave * 800 + 25000
    for idx in range(6):
        y = idx * 85.333336 + 256.0
        entries.append(SpawnEntry(960.0, y, 0.0, SPAWN_ID_10, base_right, 1))
        base_right += 100

    base_mid = (last_wave + 0xB0 + wave * 4) * 0xA0
    entries.append(SpawnEntry(512.0, 256.0, math.pi, SPAWN_ID_11, base_mid, 1))
    entries.append(SpawnEntry(512.0, 768.0, math.pi, SPAWN_ID_11, base_mid, 1))

    base_vertical = wave * 800 + 0x6F54
    entries.append(SpawnEntry(512.0, 1088.0, 3.926991, SPAWN_ID_28, base_vertical, 8))
    entries.append(SpawnEntry(512.0, -64.0, 3.926991, SPAWN_ID_28, base_vertical, 8))
    return entries

@register_quest(
    level="5.10",
    title="The Gathering",
    time_limit_ms=480000,
    start_weapon_id=1,
    unlock_weapon_id=0x1C,
    builder_address=0x004349c0,
)
def build_5_10_the_gathering(ctx: QuestContext) -> list[SpawnEntry]:
    return [
        SpawnEntry(256.0, 512.0, 0.0, SPAWN_ID_1, 500, 1),
        SpawnEntry(768.0, 512.0, 0.0, SPAWN_ID_1, 9500, 2),
        SpawnEntry(256.0, 512.0, 0.0, SPAWN_ID_58, 15500, 2),
        SpawnEntry(768.0, 512.0, 0.0, SPAWN_ID_58, 24500, 2),
        SpawnEntry(256.0, 512.0, 0.0, SPAWN_ID_0, 30500, 2),
        SpawnEntry(768.0, 512.0, 0.0, SPAWN_ID_0, 39500, 2),
        SpawnEntry(64.0, 64.0, 0.0, SPAWN_ID_60, 54500, 2),
        SpawnEntry(960.0, 64.0, 0.0, SPAWN_ID_60, 54500, 1),
        SpawnEntry(64.0, 960.0, 0.0, SPAWN_ID_60, 54500, 2),
        SpawnEntry(960.0, 960.0, 0.0, SPAWN_ID_60, 54500, 1),
        SpawnEntry(-128.0, 512.0, 0.0, SPAWN_ID_58, 90500, 6),
        SpawnEntry(1152.0, 512.0, 0.0, SPAWN_ID_1, 99500, 4),
        SpawnEntry(1152.0, 512.0, 0.0, SPAWN_ID_1, 109500, 2),
    ]


__all__ = [
    "QuestContext",
    "SpawnEntry",
    "build_5_1_the_beating",
    "build_5_2_the_spanking_of_the_dead",
    "build_5_3_the_fortress",
    "build_5_4_the_gang_wars",
    "build_5_5_knee_deep_in_the_dead",
    "build_5_6_cross_fire",
    "build_5_7_army_of_three",
    "build_5_8_monster_blues",
    "build_5_9_nagolipoli",
    "build_5_10_the_gathering",
]
