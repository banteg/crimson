from __future__ import annotations

import math

from ..perks import PerkId
from ..creatures.spawn import SpawnId
from .helpers import (
    center_point,
    ring_points,
    spawn,
)
from .registry import register_quest
from .types import QuestContext, SpawnEntry


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
        spawn(x=256.0, y=256.0, heading=0.0, spawn_id=SpawnId.ALIEN_CONST_WEAPON_BONUS_27, trigger_ms=500, count=1),
        spawn(
            x=ctx.width + 32.0,
            y=float(ctx.height // 2),
            heading=0.0,
            spawn_id=SpawnId.ALIEN_CONST_GREY_BRUTE_29,
            trigger_ms=8000,
            count=3,
        ),
    ]

    trigger = 10000
    x_offset = 0x40
    for _ in range(8):
        entries.append(
            spawn(
                x=float(ctx.width + x_offset),
                y=float(ctx.height // 2),
                heading=0.0,
                spawn_id=SpawnId.ALIEN_CONST_GREEN_SMALL_25,
                trigger_ms=trigger,
                count=8,
            )
        )
        trigger += 100
        x_offset += 0x20

    entries.append(
        spawn(
            x=-32.0,
            y=float(ctx.height // 2),
            heading=0.0,
            spawn_id=SpawnId.ALIEN_CONST_GREY_BRUTE_29,
            trigger_ms=18000,
            count=3,
        )
    )

    trigger = 20000
    x = -64
    for _ in range(8):
        entries.append(
            spawn(
                x=float(x),
                y=float(ctx.height // 2),
                heading=0.0,
                spawn_id=SpawnId.ALIEN_CONST_GREEN_SMALL_25,
                trigger_ms=trigger,
                count=8,
            )
        )
        trigger += 100
        x -= 32

    trigger = 40000
    y = -64
    for _ in range(6):
        entries.append(
            spawn(
                x=float(ctx.width // 2),
                y=float(y),
                heading=0.0,
                spawn_id=SpawnId.ALIEN_CONST_BROWN_TRANSPARENT_0F,
                trigger_ms=trigger,
                count=4,
            )
        )
        trigger += 100
        y -= 42

    trigger = 40000
    y = ctx.width + 0x2C
    for _ in range(6):
        entries.append(
            spawn(
                x=float(ctx.width // 2),
                y=float(y),
                heading=0.0,
                spawn_id=SpawnId.FORMATION_RING_ALIEN_8_12,
                trigger_ms=trigger,
                count=2,
            )
        )
        trigger += 100
        y += 0x20

    return entries


@register_quest(
    level="5.2",
    title="The Spanking Of The Dead",
    time_limit_ms=480000,
    start_weapon_id=1,
    unlock_perk_id=PerkId.DEATH_CLOCK,
    builder_address=0x004358A0,
)
def build_5_2_the_spanking_of_the_dead(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = [
        spawn(x=256.0, y=512.0, heading=0.0, spawn_id=SpawnId.ALIEN_CONST_WEAPON_BONUS_27, trigger_ms=500, count=1),
        spawn(x=768.0, y=512.0, heading=0.0, spawn_id=SpawnId.ALIEN_CONST_WEAPON_BONUS_27, trigger_ms=500, count=1),
    ]

    trigger = 5000
    step_index = 0
    while trigger < 0xA988:
        angle = step_index * 0.33333334
        radius = 512.0 - step_index * 3.8
        x = math.cos(angle) * radius + 512.0
        y = math.sin(angle) * radius + 512.0
        entries.append(
            spawn(
                x=x,
                y=y,
                heading=angle,
                spawn_id=SpawnId.ZOMBIE_RANDOM_41,
                trigger_ms=trigger,
                count=1,
            )
        )
        trigger += 300
        step_index += 1

    offset = step_index * 300
    entries.append(
        spawn(
            x=1280.0,
            y=512.0,
            heading=0.0,
            spawn_id=SpawnId.ZOMBIE_CONST_GREY_42,
            trigger_ms=offset + 10000,
            count=16,
        )
    )
    entries.append(
        spawn(
            x=-256.0,
            y=512.0,
            heading=0.0,
            spawn_id=SpawnId.ZOMBIE_CONST_GREY_42,
            trigger_ms=offset + 20000,
            count=16,
        )
    )
    return entries


@register_quest(
    level="5.3",
    title="The Fortress",
    time_limit_ms=480000,
    start_weapon_id=1,
    unlock_perk_id=PerkId.MY_FAVOURITE_WEAPON,
    builder_address=0x004352D0,
)
def build_5_3_the_fortress(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = [
        spawn(
            x=-50.0,
            y=float(ctx.height // 2),
            heading=0.0,
            spawn_id=SpawnId.SPIDER_SP1_CONST_BLUE_40,
            trigger_ms=100,
            count=6,
        ),
    ]

    trigger = 1100
    y_seed = 0x200
    while trigger < 0x14B4:
        y = y_seed * 0.125 + 256.0
        entries.append(
            spawn(
                x=768.0,
                y=float(y),
                heading=0.0,
                spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_1D_LIMITED_09,
                trigger_ms=trigger,
                count=1,
            )
        )
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
                entries.append(
                    spawn(
                        x=float(x),
                        y=float(y),
                        heading=0.0,
                        spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_32_SLOW_0A,
                        trigger_ms=trigger,
                        count=1,
                    )
                )
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
        spawn(
            x=-150.0,
            y=float(ctx.height // 2),
            heading=0.0,
            spawn_id=SpawnId.FORMATION_RING_ALIEN_8_12,
            trigger_ms=100,
            count=1,
        ),
        spawn(
            x=1174.0,
            y=float(ctx.height // 2),
            heading=0.0,
            spawn_id=SpawnId.FORMATION_RING_ALIEN_8_12,
            trigger_ms=2500,
            count=1,
        ),
    ]

    trigger = 5500
    for _ in range(10):
        entries.append(
            spawn(
                x=1174.0,
                y=float(ctx.height // 2),
                heading=0.0,
                spawn_id=SpawnId.FORMATION_RING_ALIEN_8_12,
                trigger_ms=trigger,
                count=2,
            )
        )
        trigger += 4000

    entries.append(
        spawn(
            x=512.0,
            y=1152.0,
            heading=0.0,
            spawn_id=SpawnId.FORMATION_CHAIN_ALIEN_10_13,
            trigger_ms=50500,
            count=1,
        )
    )

    trigger = 59500
    while trigger < 0x184AC:
        entries.append(
            spawn(
                x=-150.0,
                y=float(ctx.height // 2),
                heading=0.0,
                spawn_id=SpawnId.FORMATION_RING_ALIEN_8_12,
                trigger_ms=trigger,
                count=2,
            )
        )
        trigger += 4000

    entries.append(
        spawn(
            x=512.0,
            y=1152.0,
            heading=0.0,
            spawn_id=SpawnId.FORMATION_CHAIN_ALIEN_10_13,
            trigger_ms=107500,
            count=3,
        )
    )
    return entries


@register_quest(
    level="5.5",
    title="Knee-deep in the Dead",
    time_limit_ms=480000,
    start_weapon_id=1,
    unlock_perk_id=PerkId.BANDAGE,
    builder_address=0x00434F00,
)
def build_5_5_knee_deep_in_the_dead(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = [
        spawn(
            x=-50.0,
            y=float(ctx.height * 0.5),
            heading=0.0,
            spawn_id=SpawnId.ZOMBIE_CONST_GREEN_BRUTE_43,
            trigger_ms=100,
            count=1,
        ),
    ]

    trigger = 500
    wave = 0
    while trigger < 0x178F4:
        if wave % 8 == 0:
            entries.append(
                spawn(
                    x=-50.0,
                    y=float(ctx.height * 0.5),
                    heading=0.0,
                    spawn_id=SpawnId.ZOMBIE_CONST_GREEN_BRUTE_43,
                    trigger_ms=trigger - 2,
                    count=1,
                )
            )
        count = 2 if wave > 0x20 else 1
        entries.append(
            spawn(
                x=-50.0,
                y=float(ctx.height * 0.5),
                heading=0.0,
                spawn_id=SpawnId.ZOMBIE_RANDOM_41,
                trigger_ms=trigger,
                count=count,
            )
        )
        if trigger > 0x30D4:
            entries.append(
                spawn(
                    x=-50.0,
                    y=float(ctx.height * 0.5 + 158.0),
                    heading=0.0,
                    spawn_id=SpawnId.ZOMBIE_RANDOM_41,
                    trigger_ms=trigger + 500,
                    count=1,
                )
            )
        if trigger > 0x5FB4:
            entries.append(
                spawn(
                    x=-50.0,
                    y=float(ctx.height * 0.5 - 158.0),
                    heading=0.0,
                    spawn_id=SpawnId.ZOMBIE_RANDOM_41,
                    trigger_ms=trigger + 1000,
                    count=1,
                )
            )
        if trigger > 0x8E94:
            entries.append(
                spawn(
                    x=-50.0,
                    y=float(ctx.height * 0.5 - 258.0),
                    heading=0.0,
                    spawn_id=SpawnId.ZOMBIE_CONST_GREY_42,
                    trigger_ms=trigger + 0x514,
                    count=1,
                )
            )
        if trigger > 0xBD74:
            entries.append(
                spawn(
                    x=-50.0,
                    y=float(ctx.height * 0.5 + 258.0),
                    heading=0.0,
                    spawn_id=SpawnId.ZOMBIE_CONST_GREY_42,
                    trigger_ms=trigger + 300,
                    count=1,
                )
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
        spawn(
            x=1074.0,
            y=float(ctx.height * 0.5),
            heading=0.0,
            spawn_id=SpawnId.SPIDER_SP1_CONST_BLUE_40,
            trigger_ms=100,
            count=6,
        ),
        spawn(
            x=-40.0,
            y=512.0,
            heading=0.0,
            spawn_id=SpawnId.SPIDER_SP1_CONST_RANGED_VARIANT_3C,
            trigger_ms=5500,
            count=4,
        ),
        spawn(
            x=-40.0,
            y=512.0,
            heading=0.0,
            spawn_id=SpawnId.SPIDER_SP1_CONST_RANGED_VARIANT_3C,
            trigger_ms=15500,
            count=6,
        ),
        spawn(
            x=512.0,
            y=512.0,
            heading=0.0,
            spawn_id=SpawnId.SPIDER_SP2_SPLITTER_01,
            trigger_ms=18500,
            count=2,
        ),
        spawn(
            x=-100.0,
            y=512.0,
            heading=0.0,
            spawn_id=SpawnId.SPIDER_SP1_CONST_RANGED_VARIANT_3C,
            trigger_ms=25500,
            count=8,
        ),
        spawn(
            x=512.0,
            y=1152.0,
            heading=0.0,
            spawn_id=SpawnId.SPIDER_SP1_CONST_BLUE_40,
            trigger_ms=26000,
            count=6,
        ),
        spawn(
            x=512.0,
            y=-128.0,
            heading=0.0,
            spawn_id=SpawnId.SPIDER_SP1_CONST_BLUE_40,
            trigger_ms=26000,
            count=6,
        ),
    ]


@register_quest(
    level="5.7",
    title="Army of Three",
    time_limit_ms=480000,
    start_weapon_id=1,
    builder_address=0x00434CA0,
)
def build_5_7_army_of_three(ctx: QuestContext) -> list[SpawnEntry]:
    return [
        spawn(x=-64.0, y=256.0, heading=0.0, spawn_id=SpawnId.FORMATION_GRID_ALIEN_WHITE_15, trigger_ms=500, count=1),
        spawn(
            x=-64.0,
            y=512.0,
            heading=0.0,
            spawn_id=SpawnId.FORMATION_GRID_ALIEN_WHITE_15,
            trigger_ms=5500,
            count=1,
        ),
        spawn(
            x=-64.0,
            y=768.0,
            heading=0.0,
            spawn_id=SpawnId.FORMATION_GRID_ALIEN_WHITE_15,
            trigger_ms=15000,
            count=1,
        ),
        spawn(
            x=-64.0,
            y=768.0,
            heading=0.0,
            spawn_id=SpawnId.FORMATION_GRID_SPIDER_SP1_WHITE_17,
            trigger_ms=19500,
            count=1,
        ),
        spawn(
            x=-64.0,
            y=512.0,
            heading=0.0,
            spawn_id=SpawnId.FORMATION_GRID_SPIDER_SP1_WHITE_17,
            trigger_ms=22500,
            count=1,
        ),
        spawn(
            x=-64.0,
            y=256.0,
            heading=0.0,
            spawn_id=SpawnId.FORMATION_GRID_SPIDER_SP1_WHITE_17,
            trigger_ms=26500,
            count=1,
        ),
        spawn(
            x=-64.0,
            y=256.0,
            heading=0.0,
            spawn_id=SpawnId.FORMATION_GRID_LIZARD_WHITE_16,
            trigger_ms=35500,
            count=1,
        ),
        spawn(
            x=-64.0,
            y=512.0,
            heading=0.0,
            spawn_id=SpawnId.FORMATION_GRID_LIZARD_WHITE_16,
            trigger_ms=39500,
            count=1,
        ),
        spawn(
            x=-64.0,
            y=768.0,
            heading=0.0,
            spawn_id=SpawnId.FORMATION_GRID_LIZARD_WHITE_16,
            trigger_ms=42500,
            count=1,
        ),
        spawn(
            x=512.0,
            y=1152.0,
            heading=0.0,
            spawn_id=SpawnId.FORMATION_GRID_ALIEN_WHITE_15,
            trigger_ms=52500,
            count=3,
        ),
        spawn(
            x=512.0,
            y=-256.0,
            heading=0.0,
            spawn_id=SpawnId.FORMATION_GRID_SPIDER_SP1_WHITE_17,
            trigger_ms=56500,
            count=3,
        ),
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
        spawn(
            x=-50.0,
            y=float(ctx.height * 0.5),
            heading=0.0,
            spawn_id=SpawnId.LIZARD_RANDOM_04,
            trigger_ms=500,
            count=10,
        ),
        spawn(
            x=1074.0,
            y=float(ctx.height * 0.5),
            heading=0.0,
            spawn_id=SpawnId.ALIEN_RANDOM_06,
            trigger_ms=7500,
            count=10,
        ),
        spawn(
            x=512.0,
            y=1088.0,
            heading=0.0,
            spawn_id=SpawnId.SPIDER_SP1_RANDOM_03,
            trigger_ms=17500,
            count=12,
        ),
        spawn(
            x=512.0,
            y=-64.0,
            heading=0.0,
            spawn_id=SpawnId.SPIDER_SP1_RANDOM_03,
            trigger_ms=17500,
            count=12,
        ),
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
        entries.append(
            spawn(
                x=-64.0,
                y=512.0,
                heading=0.0,
                spawn_id=spawn_id,
                trigger_ms=trigger,
                count=count,
            )
        )
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

    center = center_point(ctx.width, ctx.height)
    for pos, angle in ring_points(center, 128.0, 8, step=0.7853982):
        entries.append(spawn(x=pos.x, y=pos.y, heading=angle, spawn_id=SpawnId.SPIDER_SP1_CONST_BLUE_40, trigger_ms=2000, count=1))

    for pos, angle in ring_points(center, 178.0, 12, step=0.5235988):
        entries.append(spawn(x=pos.x, y=pos.y, heading=angle, spawn_id=SpawnId.SPIDER_SP1_CONST_BLUE_40, trigger_ms=8000, count=1))

    trigger = 13000
    wave = 0
    while trigger < 0x96C8:
        count = wave // 8 + 1
        entries.extend(
            [
                spawn(
                    x=-64.0,
                    y=-64.0,
                    heading=1.0471976,
                    spawn_id=SpawnId.AI1_LIZARD_BLUE_TINT_1C,
                    trigger_ms=trigger,
                    count=count,
                ),
                spawn(
                    x=1088.0,
                    y=-64.0,
                    heading=-1.0471976,
                    spawn_id=SpawnId.AI1_LIZARD_BLUE_TINT_1C,
                    trigger_ms=trigger,
                    count=count,
                ),
                spawn(
                    x=-64.0,
                    y=1088.0,
                    heading=-1.0471976,
                    spawn_id=SpawnId.AI1_LIZARD_BLUE_TINT_1C,
                    trigger_ms=trigger,
                    count=count,
                ),
                spawn(
                    x=1088.0,
                    y=1088.0,
                    heading=3.926991,
                    spawn_id=SpawnId.AI1_LIZARD_BLUE_TINT_1C,
                    trigger_ms=trigger,
                    count=count,
                ),
            ]
        )
        trigger += 800
        wave += 1

    last_wave = max(wave - 1, 0)
    base_left = (last_wave + 0x97 + wave * 4) * 0xA0
    for idx in range(6):
        y = idx * 85.333336 + 256.0
        entries.append(
            spawn(
                x=64.0,
                y=y,
                heading=0.0,
                spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_32_SLOW_0A,
                trigger_ms=base_left,
                count=1,
            )
        )
        base_left += 100

    base_right = wave * 800 + 25000
    for idx in range(6):
        y = idx * 85.333336 + 256.0
        entries.append(
            spawn(
                x=960.0,
                y=y,
                heading=0.0,
                spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_32_SLOW_0A,
                trigger_ms=base_right,
                count=1,
            )
        )
        base_right += 100

    base_mid = (last_wave + 0xB0 + wave * 4) * 0xA0
    entries.append(
        spawn(
            x=512.0,
            y=256.0,
            heading=math.pi,
            spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_3C_SLOW_0B,
            trigger_ms=base_mid,
            count=1,
        )
    )
    entries.append(
        spawn(
            x=512.0,
            y=768.0,
            heading=math.pi,
            spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_3C_SLOW_0B,
            trigger_ms=base_mid,
            count=1,
        )
    )

    base_vertical = wave * 800 + 0x6F54
    entries.append(
        spawn(
            x=512.0,
            y=1088.0,
            heading=3.926991,
            spawn_id=SpawnId.AI1_LIZARD_BLUE_TINT_1C,
            trigger_ms=base_vertical,
            count=8,
        )
    )
    entries.append(
        spawn(
            x=512.0,
            y=-64.0,
            heading=3.926991,
            spawn_id=SpawnId.AI1_LIZARD_BLUE_TINT_1C,
            trigger_ms=base_vertical,
            count=8,
        )
    )
    return entries


@register_quest(
    level="5.10",
    title="The Gathering",
    time_limit_ms=480000,
    start_weapon_id=1,
    unlock_weapon_id=0x1C,
    builder_address=0x004349C0,
)
def build_5_10_the_gathering(ctx: QuestContext) -> list[SpawnEntry]:
    return [
        spawn(x=256.0, y=512.0, heading=0.0, spawn_id=SpawnId.SPIDER_SP2_SPLITTER_01, trigger_ms=500, count=1),
        spawn(x=768.0, y=512.0, heading=0.0, spawn_id=SpawnId.SPIDER_SP2_SPLITTER_01, trigger_ms=9500, count=2),
        spawn(
            x=256.0,
            y=512.0,
            heading=0.0,
            spawn_id=SpawnId.SPIDER_SP1_CONST_SHOCK_BOSS_3A,
            trigger_ms=15500,
            count=2,
        ),
        spawn(
            x=768.0,
            y=512.0,
            heading=0.0,
            spawn_id=SpawnId.SPIDER_SP1_CONST_SHOCK_BOSS_3A,
            trigger_ms=24500,
            count=2,
        ),
        spawn(
            x=256.0,
            y=512.0,
            heading=0.0,
            spawn_id=SpawnId.ZOMBIE_BOSS_SPAWNER_00,
            trigger_ms=30500,
            count=2,
        ),
        spawn(
            x=768.0,
            y=512.0,
            heading=0.0,
            spawn_id=SpawnId.ZOMBIE_BOSS_SPAWNER_00,
            trigger_ms=39500,
            count=2,
        ),
        spawn(x=64.0, y=64.0, heading=0.0, spawn_id=SpawnId.SPIDER_SP1_CONST_RANGED_VARIANT_3C, trigger_ms=54500, count=2),
        spawn(
            x=960.0,
            y=64.0,
            heading=0.0,
            spawn_id=SpawnId.SPIDER_SP1_CONST_RANGED_VARIANT_3C,
            trigger_ms=54500,
            count=1,
        ),
        spawn(
            x=64.0,
            y=960.0,
            heading=0.0,
            spawn_id=SpawnId.SPIDER_SP1_CONST_RANGED_VARIANT_3C,
            trigger_ms=54500,
            count=2,
        ),
        spawn(
            x=960.0,
            y=960.0,
            heading=0.0,
            spawn_id=SpawnId.SPIDER_SP1_CONST_RANGED_VARIANT_3C,
            trigger_ms=54500,
            count=1,
        ),
        spawn(
            x=-128.0,
            y=512.0,
            heading=0.0,
            spawn_id=SpawnId.SPIDER_SP1_CONST_SHOCK_BOSS_3A,
            trigger_ms=90500,
            count=6,
        ),
        spawn(
            x=1152.0,
            y=512.0,
            heading=0.0,
            spawn_id=SpawnId.SPIDER_SP2_SPLITTER_01,
            trigger_ms=99500,
            count=4,
        ),
        spawn(
            x=1152.0,
            y=512.0,
            heading=0.0,
            spawn_id=SpawnId.SPIDER_SP2_SPLITTER_01,
            trigger_ms=109500,
            count=2,
        ),
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
