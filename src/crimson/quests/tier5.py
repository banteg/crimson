from __future__ import annotations

import math

from grim.geom import Vec2

from ..creatures.spawn import SpawnId
from ..math_parity import f32, x87_pc24_add, x87_pc24_mul, x87_pc24_sub
from ..sim.state_types import TERRAIN_SIZE
from .helpers import (
    NATIVE_CENTER,
    angle_step,
    line_points,
    ring_point,
    ring_points,
    spawn,
)
from .types import QuestContext, SpawnEntry


def quest_build_the_beating(_ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = [
        spawn(Vec2(256.0, 256.0), SpawnId.ALIEN_BONUS_CARRIER_27, 500, 1),
        spawn(Vec2(TERRAIN_SIZE + 32.0, float(TERRAIN_SIZE // 2)), SpawnId.ALIEN_BIG_GRAY_29, 8000, 3),
    ]

    trigger = 10000
    x_offset = 0x40
    for _ in range(8):
        entries.append(
            spawn(
                Vec2(float(TERRAIN_SIZE + x_offset), float(TERRAIN_SIZE // 2)),
                SpawnId.ALIEN_SMALL_GREEN_MAN_25,
                trigger,
                8,
            ),
        )
        trigger += 100
        x_offset += 0x20

    entries.append(spawn(Vec2(-32.0, float(TERRAIN_SIZE // 2)), SpawnId.ALIEN_BIG_GRAY_29, 18000, 3))

    trigger = 20000
    x = -64
    for _ in range(8):
        entries.append(spawn(Vec2(float(x), float(TERRAIN_SIZE // 2)), SpawnId.ALIEN_SMALL_GREEN_MAN_25, trigger, 8))
        trigger += 100
        x -= 32

    trigger = 40000
    y = -64
    for _ in range(6):
        entries.append(spawn(Vec2(float(TERRAIN_SIZE // 2), float(y)), SpawnId.ALIEN_GHOST_0F, trigger, 4))
        trigger += 100
        y -= 42

    trigger = 40000
    y = TERRAIN_SIZE + 0x2C
    for _ in range(6):
        entries.append(spawn(Vec2(float(TERRAIN_SIZE // 2), float(y)), SpawnId.FORMATION_RING_ALIEN_8_12, trigger, 2))
        trigger += 100
        y += 0x20

    return entries


def quest_build_the_spanking_of_the_dead(_ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = [
        spawn(Vec2(256.0, 512.0), SpawnId.ALIEN_BONUS_CARRIER_27, 500, 1),
        spawn(Vec2(768.0, 512.0), SpawnId.ALIEN_BONUS_CARRIER_27, 500, 1),
    ]

    trigger = 5000
    step_index = 0
    while trigger < 0xA988:
        angle = angle_step(step_index, 0.33333334)
        radius = x87_pc24_sub(512.0, x87_pc24_mul(float(step_index), f32(3.8)))
        pos = ring_point(NATIVE_CENTER, radius, angle)
        entries.append(spawn(pos, SpawnId.ZOMBIE_RANDOM_41, trigger, 1, heading=angle))
        trigger += 300
        step_index += 1

    offset = step_index * 300
    entries.append(spawn(Vec2(1280.0, 512.0), SpawnId.ZOMBIE_SMALL_WHITE_42, offset + 10000, 16))
    entries.append(spawn(Vec2(-256.0, 512.0), SpawnId.ZOMBIE_SMALL_WHITE_42, offset + 20000, 16))
    return entries


def quest_build_the_fortress(_ctx: QuestContext) -> list[SpawnEntry]:
    half_height = TERRAIN_SIZE * 0.5
    entries: list[SpawnEntry] = [
        spawn(Vec2(-50.0, half_height), SpawnId.SPIDER_SMALL_BLUE_40, 100, 6),
    ]

    trigger = 1100
    y_seed = 0x200
    while trigger < 0x14B4:
        y = x87_pc24_add(x87_pc24_mul(float(y_seed), 0.125), 256.0)
        entries.append(spawn(Vec2(768.0, y), SpawnId.DEN_ALIEN_WEAK_SMALL_09, trigger, 1))
        trigger += 600
        y_seed += 0x200

    entry_count = 8
    x_seed = 0x180
    one_sixth = f32(0.16666667)
    while x_seed < 0x901:
        trigger = entry_count * 600 + 0x157C
        for row in range(1, 7):
            if row != 1 or x_seed not in (0x480, 0x600):
                x = x87_pc24_add(x87_pc24_mul(float(x_seed), one_sixth), 256.0)
                y = x87_pc24_sub(512.0, x87_pc24_mul(float(row * 0x180), one_sixth))
                entries.append(spawn(Vec2(x, y), SpawnId.DEN_SPIDER_BASIC_0A, trigger, 1))
                trigger += 600
                entry_count += 1
        x_seed += 0x180

    return entries


def quest_build_the_gang_wars(_ctx: QuestContext) -> list[SpawnEntry]:
    half_height = TERRAIN_SIZE * 0.5
    entries: list[SpawnEntry] = [
        spawn(Vec2(-150.0, half_height), SpawnId.FORMATION_RING_ALIEN_8_12, 100, 1),
        spawn(Vec2(1174.0, half_height), SpawnId.FORMATION_RING_ALIEN_8_12, 2500, 1),
    ]

    trigger = 5500
    for _ in range(10):
        entries.append(spawn(Vec2(1174.0, half_height), SpawnId.FORMATION_RING_ALIEN_8_12, trigger, 2))
        trigger += 4000

    entries.append(spawn(Vec2(512.0, 1152.0), SpawnId.FORMATION_CHAIN_ALIEN_10_13, 50500, 1))

    trigger = 59500
    while trigger < 0x184AC:
        entries.append(spawn(Vec2(-150.0, half_height), SpawnId.FORMATION_RING_ALIEN_8_12, trigger, 2))
        trigger += 4000

    entries.append(spawn(Vec2(512.0, 1152.0), SpawnId.FORMATION_CHAIN_ALIEN_10_13, 107500, 3))
    return entries


def quest_build_knee_deep_in_the_dead(_ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = [
        spawn(Vec2(-50.0, float(TERRAIN_SIZE * 0.5)), SpawnId.ZOMBIE_CONST_GREEN_BRUTE_43, 100, 1),
    ]

    trigger = 500
    wave = 0
    while trigger < 0x178F4:
        if wave % 8 == 0:
            entries.append(
                spawn(Vec2(-50.0, float(TERRAIN_SIZE * 0.5)), SpawnId.ZOMBIE_CONST_GREEN_BRUTE_43, trigger - 2, 1),
            )
        count = 2 if wave > 0x20 else 1
        entries.append(spawn(Vec2(-50.0, float(TERRAIN_SIZE * 0.5)), SpawnId.ZOMBIE_RANDOM_41, trigger, count))
        if trigger > 0x30D4:
            entries.append(
                spawn(Vec2(-50.0, float(TERRAIN_SIZE * 0.5 + 158.0)), SpawnId.ZOMBIE_RANDOM_41, trigger + 500, 1),
            )
        if trigger > 0x5FB4:
            entries.append(
                spawn(Vec2(-50.0, float(TERRAIN_SIZE * 0.5 - 158.0)), SpawnId.ZOMBIE_RANDOM_41, trigger + 1000, 1),
            )
        if trigger > 0x8E94:
            entries.append(
                spawn(
                    Vec2(-50.0, float(TERRAIN_SIZE * 0.5 - 258.0)),
                    SpawnId.ZOMBIE_SMALL_WHITE_42,
                    trigger + 0x514,
                    1,
                ),
            )
        if trigger > 0xBD74:
            entries.append(
                spawn(Vec2(-50.0, float(TERRAIN_SIZE * 0.5 + 258.0)), SpawnId.ZOMBIE_SMALL_WHITE_42, trigger + 300, 1),
            )
        trigger += 0x5DC
        wave += 1

    return entries


def quest_build_cross_fire(_ctx: QuestContext) -> list[SpawnEntry]:
    return [
        spawn(Vec2(1074.0, float(TERRAIN_SIZE * 0.5)), SpawnId.SPIDER_SMALL_BLUE_40, 100, 6),
        spawn(Vec2(-40.0, 512.0), SpawnId.SPIDER_PLASMA_SHOOTER_3C, 5500, 4),
        spawn(Vec2(-40.0, 512.0), SpawnId.SPIDER_PLASMA_SHOOTER_3C, 15500, 6),
        spawn(Vec2(512.0, 512.0), SpawnId.SPIDER_SP2_SPLITTER_01, 18500, 2),
        spawn(Vec2(-100.0, 512.0), SpawnId.SPIDER_PLASMA_SHOOTER_3C, 25500, 8),
        spawn(Vec2(512.0, 1152.0), SpawnId.SPIDER_SMALL_BLUE_40, 26000, 6),
        spawn(Vec2(512.0, -128.0), SpawnId.SPIDER_SMALL_BLUE_40, 26000, 6),
    ]


def quest_build_army_of_three(_ctx: QuestContext) -> list[SpawnEntry]:
    return [
        spawn(Vec2(-64.0, 256.0), SpawnId.FORMATION_GRID_ALIEN_WHITE_15, 500, 1),
        spawn(Vec2(-64.0, 512.0), SpawnId.FORMATION_GRID_ALIEN_WHITE_15, 5500, 1),
        spawn(Vec2(-64.0, 768.0), SpawnId.FORMATION_GRID_ALIEN_WHITE_15, 15000, 1),
        spawn(Vec2(-64.0, 768.0), SpawnId.FORMATION_GRID_SPIDER_SP1_WHITE_17, 19500, 1),
        spawn(Vec2(-64.0, 512.0), SpawnId.FORMATION_GRID_SPIDER_SP1_WHITE_17, 22500, 1),
        spawn(Vec2(-64.0, 256.0), SpawnId.FORMATION_GRID_SPIDER_SP1_WHITE_17, 26500, 1),
        spawn(Vec2(-64.0, 256.0), SpawnId.FORMATION_GRID_LIZARD_WHITE_16, 35500, 1),
        spawn(Vec2(-64.0, 512.0), SpawnId.FORMATION_GRID_LIZARD_WHITE_16, 39500, 1),
        spawn(Vec2(-64.0, 768.0), SpawnId.FORMATION_GRID_LIZARD_WHITE_16, 42500, 1),
        spawn(Vec2(512.0, 1152.0), SpawnId.FORMATION_GRID_ALIEN_WHITE_15, 52500, 3),
        spawn(Vec2(512.0, -256.0), SpawnId.FORMATION_GRID_SPIDER_SP1_WHITE_17, 56500, 3),
    ]


def quest_build_monster_blues(_ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = [
        spawn(Vec2(-50.0, float(TERRAIN_SIZE * 0.5)), SpawnId.LIZARD_RANDOM_04, 500, 10),
        spawn(Vec2(1074.0, float(TERRAIN_SIZE * 0.5)), SpawnId.ALIEN_RANDOM_06, 7500, 10),
        spawn(Vec2(512.0, 1088.0), SpawnId.SPIDER_SP1_RANDOM_03, 17500, 12),
        spawn(Vec2(512.0, -64.0), SpawnId.SPIDER_SP1_RANDOM_03, 17500, 12),
    ]

    trigger = 27500
    for idx in range(0x40):
        if idx % 4 == 0:
            spawn_id = SpawnId.ALIEN_RANDOM_06
        elif idx % 4 == 1:
            spawn_id = SpawnId.SPIDER_SP1_RANDOM_03
        else:
            spawn_id = SpawnId.SPIDER_SP2_RANDOM_05
        count = idx // 8 + 2
        entries.append(spawn(Vec2(-64.0, 512.0), spawn_id, trigger, count))
        trigger += 900
    return entries


def quest_build_nagolipoli(_ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []

    for pos, angle in ring_points(NATIVE_CENTER, 128.0, 8, step=0.7853982):
        entries.append(spawn(pos, SpawnId.SPIDER_SMALL_BLUE_40, 2000, 1, heading=angle))

    for pos, angle in ring_points(NATIVE_CENTER, 178.0, 12, step=0.5235988):
        entries.append(spawn(pos, SpawnId.SPIDER_SMALL_BLUE_40, 8000, 1, heading=angle))

    trigger = 13000
    wave = 0
    while trigger < 0x96C8:
        count = wave // 8 + 1
        entries.extend(
            [
                spawn(Vec2(-64.0, -64.0), SpawnId.AI1_LIZARD_BLUE_TINT_1C, trigger, count, heading=1.0471976),
                spawn(Vec2(1088.0, -64.0), SpawnId.AI1_LIZARD_BLUE_TINT_1C, trigger, count, heading=-1.0471976),
                spawn(Vec2(-64.0, 1088.0), SpawnId.AI1_LIZARD_BLUE_TINT_1C, trigger, count, heading=-1.0471976),
                spawn(Vec2(1088.0, 1088.0), SpawnId.AI1_LIZARD_BLUE_TINT_1C, trigger, count, heading=3.926991),
            ],
        )
        trigger += 800
        wave += 1

    last_wave = max(wave - 1, 0)
    base_left = (last_wave + 0x97 + wave * 4) * 0xA0
    for pos in line_points(Vec2(64.0, 256.0), Vec2(0.0, 85.333336), 6):
        entries.append(spawn(pos, SpawnId.DEN_SPIDER_BASIC_0A, base_left, 1))
        base_left += 100

    base_right = wave * 800 + 25000
    for pos in line_points(Vec2(960.0, 256.0), Vec2(0.0, 85.333336), 6):
        entries.append(spawn(pos, SpawnId.DEN_SPIDER_BASIC_0A, base_right, 1))
        base_right += 100

    base_mid = (last_wave + 0xB0 + wave * 4) * 0xA0
    entries.append(spawn(Vec2(512.0, 256.0), SpawnId.DEN_SPIDER_PLASMA_SHOOTERS_0B, base_mid, 1, heading=math.pi))
    entries.append(spawn(Vec2(512.0, 768.0), SpawnId.DEN_SPIDER_PLASMA_SHOOTERS_0B, base_mid, 1, heading=math.pi))

    base_vertical = wave * 800 + 0x6F54
    entries.append(spawn(Vec2(512.0, 1088.0), SpawnId.AI1_LIZARD_BLUE_TINT_1C, base_vertical, 8, heading=3.926991))
    entries.append(spawn(Vec2(512.0, -64.0), SpawnId.AI1_LIZARD_BLUE_TINT_1C, base_vertical, 8, heading=3.926991))
    return entries


def quest_build_the_gathering(_ctx: QuestContext) -> list[SpawnEntry]:
    return [
        spawn(Vec2(256.0, 512.0), SpawnId.SPIDER_SP2_SPLITTER_01, 500, 1),
        spawn(Vec2(768.0, 512.0), SpawnId.SPIDER_SP2_SPLITTER_01, 9500, 2),
        spawn(Vec2(256.0, 512.0), SpawnId.SPIDER_BOSS_3A, 15500, 2),
        spawn(Vec2(768.0, 512.0), SpawnId.SPIDER_BOSS_3A, 24500, 2),
        spawn(Vec2(256.0, 512.0), SpawnId.ZOMBIE_BOSS_SPAWNER_00, 30500, 2),
        spawn(Vec2(768.0, 512.0), SpawnId.ZOMBIE_BOSS_SPAWNER_00, 39500, 2),
        spawn(Vec2(64.0, 64.0), SpawnId.SPIDER_PLASMA_SHOOTER_3C, 54500, 2),
        spawn(Vec2(960.0, 64.0), SpawnId.SPIDER_PLASMA_SHOOTER_3C, 54500, 1),
        spawn(Vec2(64.0, 960.0), SpawnId.SPIDER_PLASMA_SHOOTER_3C, 54500, 2),
        spawn(Vec2(960.0, 960.0), SpawnId.SPIDER_PLASMA_SHOOTER_3C, 54500, 1),
        spawn(Vec2(-128.0, 512.0), SpawnId.SPIDER_BOSS_3A, 90500, 6),
        spawn(Vec2(1152.0, 512.0), SpawnId.SPIDER_SP2_SPLITTER_01, 99500, 4),
        spawn(Vec2(1152.0, 512.0), SpawnId.SPIDER_SP2_SPLITTER_01, 109500, 2),
    ]


__all__ = [
    "QuestContext",
    "SpawnEntry",
    "quest_build_army_of_three",
    "quest_build_cross_fire",
    "quest_build_knee_deep_in_the_dead",
    "quest_build_monster_blues",
    "quest_build_nagolipoli",
    "quest_build_the_beating",
    "quest_build_the_fortress",
    "quest_build_the_gang_wars",
    "quest_build_the_gathering",
    "quest_build_the_spanking_of_the_dead",
]
