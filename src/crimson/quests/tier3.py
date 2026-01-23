from __future__ import annotations

import random

from ..perks import PerkId
from .helpers import (
    center_point,
    edge_midpoints,
    line_points_x,
    line_points_y,
    radial_points,
    random_angle,
    ring_points,
    spawn,
    spawn_at,
)
from .registry import register_quest
from .types import QuestContext, SpawnEntry

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


@register_quest(
    level="3.1",
    title="The Blighting",
    time_limit_ms=300000,
    start_weapon_id=1,
    unlock_perk_id=PerkId.TOXIC_AVENGER,
    builder_address=0x00438050,
)
def build_3_1_the_blighting(ctx: QuestContext) -> list[SpawnEntry]:
    edges = edge_midpoints(ctx.width)
    edges_wide = edge_midpoints(ctx.width, offset=128.0)
    entries = [
        spawn_at(
            edges_wide.right,
            heading=0.0,
            spawn_id=SPAWN_ID_43,
            trigger_ms=1500,
            count=2,
        ),
        spawn_at(edges_wide.left, heading=0.0, spawn_id=SPAWN_ID_43, trigger_ms=1500, count=2),
        spawn(x=896.0, y=128.0, heading=0.0, spawn_id=SPAWN_ID_7, trigger_ms=2000, count=1),
        spawn(x=128.0, y=128.0, heading=0.0, spawn_id=SPAWN_ID_7, trigger_ms=2000, count=1),
        spawn(x=128.0, y=896.0, heading=0.0, spawn_id=SPAWN_ID_7, trigger_ms=2000, count=1),
        spawn(x=896.0, y=896.0, heading=0.0, spawn_id=SPAWN_ID_7, trigger_ms=2000, count=1),
    ]

    trigger = 4000
    for wave in range(8):
        if wave in (2, 4):
            entries.append(
                spawn_at(
                    edges_wide.left,
                    heading=0.0,
                    spawn_id=SPAWN_ID_43,
                    trigger_ms=trigger,
                    count=4,
                )
            )
        if wave in (3, 5):
            entries.append(
                spawn_at(
                    edges_wide.right,
                    heading=0.0,
                    spawn_id=SPAWN_ID_43,
                    trigger_ms=trigger,
                    count=4,
                )
            )
        spawn_id = SPAWN_ID_26 if wave % 2 == 0 else SPAWN_ID_28
        edge = wave % 5
        if edge == 0:
            entries.append(
                spawn_at(
                    edges.right,
                    heading=0.0,
                    spawn_id=spawn_id,
                    trigger_ms=trigger,
                    count=12,
                )
            )
            trigger += 15000
        elif edge == 1:
            entries.append(
                spawn_at(
                    edges.left,
                    heading=0.0,
                    spawn_id=spawn_id,
                    trigger_ms=trigger,
                    count=12,
                )
            )
            trigger += 15000
        elif edge == 2:
            entries.append(
                spawn_at(
                    edges.bottom,
                    heading=0.0,
                    spawn_id=spawn_id,
                    trigger_ms=trigger,
                    count=12,
                )
            )
            trigger += 15000
        elif edge == 3:
            entries.append(
                spawn_at(
                    edges.top,
                    heading=0.0,
                    spawn_id=spawn_id,
                    trigger_ms=trigger,
                    count=12,
                )
            )
            trigger += 15000
        trigger += 1000
    return entries


@register_quest(
    level="3.2",
    title="Lizard Kings",
    time_limit_ms=180000,
    start_weapon_id=1,
    unlock_weapon_id=0x0A,
    builder_address=0x00437710,
)
def build_3_2_lizard_kings(ctx: QuestContext) -> list[SpawnEntry]:
    center_x, center_y = center_point(ctx.width, ctx.height)
    entries = [
        spawn(
            x=1152.0,
            y=512.0,
            heading=0.0,
            spawn_id=SPAWN_ID_17,
            trigger_ms=1500,
            count=1,
        ),
        spawn(
            x=-128.0,
            y=512.0,
            heading=0.0,
            spawn_id=SPAWN_ID_17,
            trigger_ms=1500,
            count=1,
        ),
        spawn(
            x=1152.0,
            y=896.0,
            heading=0.0,
            spawn_id=SPAWN_ID_17,
            trigger_ms=1500,
            count=1,
        ),
    ]
    trigger = 1500
    for x, y, angle in ring_points(center_x, center_y, 256.0, 28, step=0.34906587):
        entries.append(
            spawn(
                x=x,
                y=y,
                heading=-angle,
                spawn_id=SPAWN_ID_49,
                trigger_ms=trigger,
                count=1,
            )
        )
        trigger += 900
    return entries


@register_quest(
    level="3.3",
    title="The Killing",
    time_limit_ms=300000,
    start_weapon_id=1,
    unlock_perk_id=PerkId.REGENERATION,
    builder_address=0x004384A0,
)
def build_3_3_the_killing(ctx: QuestContext, rng: random.Random | None = None) -> list[SpawnEntry]:
    rng = rng or random.Random()
    edges = edge_midpoints(ctx.width)
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
                spawn_at(
                    edges.right,
                    heading=0.0,
                    spawn_id=spawn_id,
                    trigger_ms=trigger,
                    count=12,
                )
            )
        elif edge == 1:
            entries.append(
                spawn_at(
                    edges.left,
                    heading=0.0,
                    spawn_id=spawn_id,
                    trigger_ms=trigger,
                    count=12,
                )
            )
        elif edge == 2:
            entries.append(
                spawn_at(
                    edges.bottom,
                    heading=0.0,
                    spawn_id=spawn_id,
                    trigger_ms=trigger,
                    count=12,
                )
            )
        elif edge == 3:
            entries.append(
                spawn_at(
                    edges.top,
                    heading=0.0,
                    spawn_id=spawn_id,
                    trigger_ms=trigger,
                    count=12,
                )
            )
        else:
            for offset in (0, 1000, 2000):
                x = rng.randrange(0x300) + 0x80
                y = rng.randrange(0x300) + 0x80
                entries.append(
                    spawn(
                        x=float(x),
                        y=float(y),
                        heading=0.0,
                        spawn_id=SPAWN_ID_7,
                        trigger_ms=trigger + offset,
                        count=3,
                    )
                )

        trigger += 6000
    return entries


@register_quest(
    level="3.4",
    title="Hidden Evil",
    time_limit_ms=300000,
    start_weapon_id=1,
    unlock_weapon_id=0x0D,
    builder_address=0x00435A30,
)
def build_3_4_hidden_evil(ctx: QuestContext) -> list[SpawnEntry]:
    edges = edge_midpoints(ctx.width, ctx.height)
    return [
        spawn_at(edges.bottom, heading=0.0, spawn_id=SPAWN_ID_33, trigger_ms=500, count=50),
        spawn_at(edges.bottom, heading=0.0, spawn_id=SPAWN_ID_34, trigger_ms=15000, count=30),
        spawn_at(edges.bottom, heading=0.0, spawn_id=SPAWN_ID_35, trigger_ms=25000, count=20),
        spawn_at(edges.bottom, heading=0.0, spawn_id=SPAWN_ID_35, trigger_ms=30000, count=30),
        spawn_at(edges.bottom, heading=0.0, spawn_id=SPAWN_ID_34, trigger_ms=35000, count=30),
    ]


@register_quest(
    level="3.5",
    title="Surrounded By Reptiles",
    time_limit_ms=300000,
    start_weapon_id=1,
    unlock_perk_id=PerkId.PYROMANIAC,
    builder_address=0x00438940,
)
def build_3_5_surrounded_by_reptiles(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    trigger = 1000
    for _x, y in line_points_y(256.0, 102.4, 5, 256.0):
        entries.append(
            spawn(
                x=256.0,
                y=y,
                heading=0.0,
                spawn_id=SPAWN_ID_13,
                trigger_ms=trigger,
                count=1,
            )
        )
        entries.append(
            spawn(
                x=768.0,
                y=y,
                heading=0.0,
                spawn_id=SPAWN_ID_13,
                trigger_ms=trigger,
                count=1,
            )
        )
        trigger += 800

    trigger = 8000
    for x, _y in line_points_x(256.0, 102.4, 5, 256.0):
        entries.append(
            spawn(
                x=x,
                y=256.0,
                heading=0.0,
                spawn_id=SPAWN_ID_13,
                trigger_ms=trigger,
                count=1,
            )
        )
        entries.append(
            spawn(
                x=x,
                y=768.0,
                heading=0.0,
                spawn_id=SPAWN_ID_13,
                trigger_ms=trigger,
                count=1,
            )
        )
        trigger += 800
    return entries


@register_quest(
    level="3.6",
    title="The Lizquidation",
    time_limit_ms=300000,
    start_weapon_id=1,
    unlock_weapon_id=0x0F,
    builder_address=0x00437C70,
)
def build_3_6_the_lizquidation(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    edges = edge_midpoints(ctx.width)
    trigger = 1500
    for wave in range(10):
        count = wave + 6
        entries.append(
            spawn_at(
                edges.right,
                heading=0.0,
                spawn_id=SPAWN_ID_46,
                trigger_ms=trigger,
                count=count,
            )
        )
        entries.append(
            spawn_at(
                edges.left,
                heading=0.0,
                spawn_id=SPAWN_ID_46,
                trigger_ms=trigger,
                count=count,
            )
        )
        if wave == 4:
            entries.append(
                spawn(
                    x=ctx.width + 128.0,
                    y=edges.right[1],
                    heading=0.0,
                    spawn_id=SPAWN_ID_43,
                    trigger_ms=1500,
                    count=2,
                )
            )
        trigger += 8000
    return entries


@register_quest(
    level="3.7",
    title="Spiders Inc.",
    time_limit_ms=300000,
    start_weapon_id=11,
    unlock_perk_id=PerkId.NINJA,
    builder_address=0x004390D0,
)
def build_3_7_spiders_inc(ctx: QuestContext) -> list[SpawnEntry]:
    edges = edge_midpoints(ctx.width)
    center_x, _center_y = center_point(ctx.width, ctx.height)
    entries = [
        spawn_at(edges.bottom, heading=0.0, spawn_id=SPAWN_ID_56, trigger_ms=500, count=1),
        spawn(
            x=center_x + 64.0,
            y=edges.bottom[1],
            heading=0.0,
            spawn_id=SPAWN_ID_56,
            trigger_ms=500,
            count=1,
        ),
        spawn_at(edges.top, heading=0.0, spawn_id=SPAWN_ID_64, trigger_ms=500, count=4),
    ]

    trigger = 17000
    step_count = 0
    while trigger < 107000:
        count = step_count // 2 + 3
        entries.append(
            spawn_at(
                edges.bottom,
                heading=0.0,
                spawn_id=SPAWN_ID_56,
                trigger_ms=trigger,
                count=count,
            )
        )
        entries.append(
            spawn_at(
                edges.top,
                heading=0.0,
                spawn_id=SPAWN_ID_56,
                trigger_ms=trigger,
                count=count,
            )
        )
        trigger += 6000
        step_count += 1
    return entries


@register_quest(
    level="3.8",
    title="Lizard Raze",
    time_limit_ms=300000,
    start_weapon_id=1,
    unlock_weapon_id=0x12,
    builder_address=0x00438840,
)
def build_3_8_lizard_raze(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    edges = edge_midpoints(ctx.width)
    trigger = 1500
    while trigger < 91500:
        entries.append(
            spawn_at(
                edges.right,
                heading=0.0,
                spawn_id=SPAWN_ID_46,
                trigger_ms=trigger,
                count=6,
            )
        )
        entries.append(
            spawn_at(
                edges.left,
                heading=0.0,
                spawn_id=SPAWN_ID_46,
                trigger_ms=trigger,
                count=6,
            )
        )
        trigger += 6000
    entries.extend(
        [
            spawn(
                x=128.0,
                y=256.0,
                heading=0.0,
                spawn_id=SPAWN_ID_12,
                trigger_ms=10000,
                count=1,
            ),
            spawn(
                x=128.0,
                y=384.0,
                heading=0.0,
                spawn_id=SPAWN_ID_12,
                trigger_ms=10000,
                count=1,
            ),
            spawn(
                x=128.0,
                y=512.0,
                heading=0.0,
                spawn_id=SPAWN_ID_12,
                trigger_ms=10000,
                count=1,
            ),
        ]
    )
    return entries


@register_quest(
    level="3.9",
    title="Deja vu",
    time_limit_ms=120000,
    start_weapon_id=6,
    unlock_perk_id=PerkId.HIGHLANDER,
    builder_address=0x00437920,
)
def build_3_9_deja_vu(ctx: QuestContext, rng: random.Random | None = None) -> list[SpawnEntry]:
    rng = rng or random.Random()
    entries: list[SpawnEntry] = []
    center_x, center_y = center_point(ctx.width, ctx.height)
    trigger = 2000
    step = 2000
    while step > 560:
        angle = random_angle(rng)
        for x, y in radial_points(center_x, center_y, angle, 0x54, 0xFC, 0x2A):
            entries.append(
                spawn(
                    x=x,
                    y=y,
                    heading=0.0,
                    spawn_id=SPAWN_ID_13,
                    trigger_ms=trigger,
                    count=1,
                )
            )
        trigger += step
        step -= 0x50
    return entries


@register_quest(
    level="3.10",
    title="Zombie Masters",
    time_limit_ms=300000,
    start_weapon_id=1,
    unlock_weapon_id=0x14,
    builder_address=0x004360A0,
)
def build_3_10_zombie_masters(ctx: QuestContext) -> list[SpawnEntry]:
    return [
        spawn(
            x=256.0,
            y=256.0,
            heading=0.0,
            spawn_id=SPAWN_ID_0,
            trigger_ms=1000,
            count=ctx.player_count,
        ),
        spawn(x=512.0, y=256.0, heading=0.0, spawn_id=SPAWN_ID_0, trigger_ms=6000, count=1),
        spawn(
            x=768.0,
            y=256.0,
            heading=0.0,
            spawn_id=SPAWN_ID_0,
            trigger_ms=14000,
            count=ctx.player_count,
        ),
        spawn(
            x=768.0,
            y=768.0,
            heading=0.0,
            spawn_id=SPAWN_ID_0,
            trigger_ms=18000,
            count=1,
        ),
    ]


__all__ = [
    "QuestContext",
    "SpawnEntry",
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
