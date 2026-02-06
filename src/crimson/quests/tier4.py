from __future__ import annotations

from ..perks import PerkId
from ..creatures.spawn import SpawnId
from .helpers import (
    center_point,
    edge_midpoints,
    ring_points,
    spawn,
    spawn_at,
)
from .registry import register_quest
from .types import QuestContext, SpawnEntry
from grim.geom import Vec2


@register_quest(
    level="4.1",
    title="Major Alien Breach",
    time_limit_ms=300000,
    start_weapon_id=18,
    unlock_perk_id=PerkId.JINXED,
    builder_address=0x00437AF0,
)
def build_4_1_major_alien_breach(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    edges = edge_midpoints(ctx.width)
    trigger = 4000
    for offset in range(0, 0x5DC, 0xF):
        entries.append(
            spawn_at(
                edges.right,
                heading=0.0,
                spawn_id=SpawnId.ALIEN_RANDOM_GREEN_20,
                trigger_ms=trigger,
                count=2,
            )
        )
        entries.append(
            spawn_at(
                edges.top,
                heading=0.0,
                spawn_id=SpawnId.ALIEN_RANDOM_GREEN_20,
                trigger_ms=trigger,
                count=2,
            )
        )
        trigger += 2000 - offset
        if trigger < 1000:
            trigger = 1000
    return entries


@register_quest(
    level="4.2",
    title="Zombie Time",
    time_limit_ms=300000,
    start_weapon_id=1,
    unlock_weapon_id=0x13,
    builder_address=0x00437D70,
)
def build_4_2_zombie_time(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    edges = edge_midpoints(ctx.width)
    trigger = 1500
    while trigger < 0x17CDC:
        entries.append(
            spawn_at(
                edges.right,
                heading=0.0,
                spawn_id=SpawnId.ZOMBIE_RANDOM_41,
                trigger_ms=trigger,
                count=8,
            )
        )
        entries.append(
            spawn_at(
                edges.left,
                heading=0.0,
                spawn_id=SpawnId.ZOMBIE_RANDOM_41,
                trigger_ms=trigger,
                count=8,
            )
        )
        trigger += 8000
    return entries


@register_quest(
    level="4.3",
    title="Lizard Zombie Pact",
    time_limit_ms=300000,
    start_weapon_id=1,
    unlock_perk_id=PerkId.PERK_MASTER,
    builder_address=0x00438700,
)
def build_4_3_lizard_zombie_pact(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    edges = edge_midpoints(ctx.width)
    trigger = 1500
    wave = 0
    while trigger < 0x1BB5C:
        entries.append(
            spawn_at(
                edges.right,
                heading=0.0,
                spawn_id=SpawnId.ZOMBIE_RANDOM_41,
                trigger_ms=trigger,
                count=6,
            )
        )
        entries.append(
            spawn_at(
                edges.left,
                heading=0.0,
                spawn_id=SpawnId.ZOMBIE_RANDOM_41,
                trigger_ms=trigger,
                count=6,
            )
        )
        if wave % 5 == 0:
            idx = wave // 5
            entries.append(
                spawn(
                    Vec2(356.0, float(idx * 0xB4 + 0x100)),
                    heading=0.0,
                    spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_31_FAST_0C,
                    trigger_ms=trigger,
                    count=idx + 1,
                )
            )
            entries.append(
                spawn(
                    Vec2(356.0, float(idx * 0xB4 + 0x180)),
                    heading=0.0,
                    spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_31_FAST_0C,
                    trigger_ms=trigger,
                    count=idx + 2,
                )
            )
        trigger += 7000
        wave += 1
    return entries


@register_quest(
    level="4.4",
    title="The Collaboration",
    time_limit_ms=360000,
    start_weapon_id=1,
    unlock_weapon_id=0x0E,
    builder_address=0x00437F30,
)
def build_4_4_the_collaboration(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    edges = edge_midpoints(ctx.width)
    trigger = 1500
    wave = 0
    while trigger < 0x2B55C:
        count = int(wave * 0.8 + 7)
        entries.append(
            spawn_at(
                edges.right,
                heading=0.0,
                spawn_id=SpawnId.AI1_ALIEN_BLUE_TINT_1A,
                trigger_ms=trigger,
                count=count,
            )
        )
        entries.append(
            spawn_at(
                edges.bottom,
                heading=0.0,
                spawn_id=SpawnId.AI1_SPIDER_SP1_BLUE_TINT_1B,
                trigger_ms=trigger,
                count=count,
            )
        )
        entries.append(
            spawn_at(
                edges.left,
                heading=0.0,
                spawn_id=SpawnId.AI1_LIZARD_BLUE_TINT_1C,
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
        trigger += 11000
        wave += 1
    return entries


@register_quest(
    level="4.5",
    title="The Massacre",
    time_limit_ms=300000,
    start_weapon_id=1,
    unlock_perk_id=PerkId.REFLEX_BOOSTED,
    builder_address=0x004383E0,
)
def build_4_5_the_massacre(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    edges = edge_midpoints(ctx.width)
    edges_wide = edge_midpoints(ctx.width, offset=128.0)
    trigger = 1500
    wave = 0
    while trigger < 0x1656C:
        entries.append(
            spawn_at(
                edges.right,
                heading=0.0,
                spawn_id=SpawnId.ZOMBIE_RANDOM_41,
                trigger_ms=trigger,
                count=wave + 3,
            )
        )
        if wave % 2 == 0:
            entries.append(
                spawn_at(
                    edges_wide.right,
                    heading=0.0,
                    spawn_id=SpawnId.ALIEN_CONST_RED_FAST_2B,
                    trigger_ms=trigger,
                    count=wave + 1,
                )
            )
        trigger += 5000
        wave += 1
    return entries


@register_quest(
    level="4.6",
    title="The Unblitzkrieg",
    time_limit_ms=600000,
    start_weapon_id=1,
    unlock_weapon_id=0x11,
    builder_address=0x00438A40,
)
def build_4_6_the_unblitzkrieg(ctx: QuestContext) -> list[SpawnEntry]:
    def spawn_id_for(toggle: bool) -> SpawnId:
        return SpawnId.ALIEN_SPAWNER_CHILD_31_SLOW_0D if toggle else SpawnId.ALIEN_SPAWNER_CHILD_1D_FAST_07

    entries: list[SpawnEntry] = []
    trigger = 500

    i_var5 = 0
    for idx in range(10):
        y = float(i_var5 // 10 + 200)
        entries.append(
            spawn(
                Vec2(824.0, y),
                heading=0.0,
                spawn_id=spawn_id_for(idx % 2 == 1),
                trigger_ms=trigger,
                count=1,
            )
        )
        trigger += 1800
        i_var5 += 0x270

    i_var5 = 0
    toggle = False
    for _ in range(10):
        x = float(0x338 - i_var5 // 10)
        entries.append(
            spawn(
                Vec2(x, 824.0),
                heading=0.0,
                spawn_id=spawn_id_for(toggle),
                trigger_ms=trigger,
                count=1,
            )
        )
        trigger += 1500
        toggle = not toggle
        i_var5 += 0x270

    entries.append(
        spawn(
            Vec2(512.0, 512.0),
            heading=0.0,
            spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_1D_FAST_07,
            trigger_ms=trigger,
            count=1,
        )
    )

    i_var5 = 0
    toggle = False
    for _ in range(10):
        y = float(0x338 - i_var5 // 10)
        entries.append(
            spawn(
                Vec2(200.0, y),
                heading=0.0,
                spawn_id=spawn_id_for(toggle),
                trigger_ms=trigger,
                count=1,
            )
        )
        trigger += 1200
        toggle = not toggle
        i_var5 += 0x270

    i_var5 = 0
    toggle = False
    for _ in range(10):
        x = float(i_var5 // 10 + 200)
        entries.append(
            spawn(
                Vec2(x, 200.0),
                heading=0.0,
                spawn_id=spawn_id_for(toggle),
                trigger_ms=trigger,
                count=1,
            )
        )
        trigger += 800
        toggle = not toggle
        i_var5 += 0x270

    i_var5 = 0
    toggle = False
    for _ in range(10):
        y = float(i_var5 // 10 + 200)
        entries.append(
            spawn(
                Vec2(824.0, y),
                heading=0.0,
                spawn_id=spawn_id_for(toggle),
                trigger_ms=trigger,
                count=1,
            )
        )
        trigger += 800
        toggle = not toggle
        i_var5 += 0x270

    i_var5 = 0
    toggle = False
    for _ in range(10):
        x = float(0x338 - i_var5 // 10)
        entries.append(
            spawn(
                Vec2(x, 824.0),
                heading=0.0,
                spawn_id=spawn_id_for(toggle),
                trigger_ms=trigger,
                count=1,
            )
        )
        trigger += 700
        toggle = not toggle
        i_var5 += 0x270

    i_var5 = 0
    toggle = False
    for _ in range(10):
        y = float(0x338 - i_var5 // 10)
        entries.append(
            spawn(
                Vec2(200.0, y),
                heading=0.0,
                spawn_id=spawn_id_for(toggle),
                trigger_ms=trigger,
                count=1,
            )
        )
        trigger += 700
        toggle = not toggle
        i_var5 += 0x270

    i_var5 = 0
    toggle = False
    for _ in range(10):
        x = float(i_var5 // 10 + 200)
        entries.append(
            spawn(
                Vec2(x, 200.0),
                heading=0.0,
                spawn_id=spawn_id_for(toggle),
                trigger_ms=trigger,
                count=1,
            )
        )
        trigger += 800
        toggle = not toggle
        i_var5 += 0x270
    return entries


@register_quest(
    level="4.7",
    title="Gauntlet",
    time_limit_ms=300000,
    start_weapon_id=1,
    unlock_perk_id=PerkId.GREATER_REGENERATION,
    builder_address=0x004369A0,
)
def build_4_7_gauntlet(ctx: QuestContext, full_version: bool = True) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    player_count = ctx.player_count + (4 if full_version else 0)
    center = center_point(ctx.width, ctx.height)
    edges = edge_midpoints(ctx.width)

    ring_count = player_count + 9
    if ring_count > 0:
        trigger = 0
        for pos, _angle in ring_points(center, 158.0, ring_count):
            entries.append(
                spawn(
                    pos,
                    heading=0.0,
                    spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_32_SLOW_0A,
                    trigger_ms=trigger,
                    count=1,
                )
            )
            trigger += 200

    if ring_count > 0:
        trigger = 4000
        for count in range(2, ring_count + 2):
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

    outer_count = player_count + 0x11
    if outer_count > 0:
        trigger = 42500
        for pos, _angle in ring_points(center, 258.0, outer_count):
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
    return entries


@register_quest(
    level="4.8",
    title="Syntax Terror",
    time_limit_ms=300000,
    start_weapon_id=1,
    unlock_weapon_id=0x16,
    builder_address=0x00436C10,
)
def build_4_8_syntax_terror(ctx: QuestContext, full_version: bool = True) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    player_count = ctx.player_count + (4 if full_version else 0)
    outer_seed = 0x14C9
    outer_index = 0
    trigger_base = 1500
    while outer_seed < 0x159D:
        if player_count + 9 > 0:
            trigger = trigger_base
            inner_seed = 0x4C5
            for i in range(player_count + 9):
                x = (((i * i * 0x4C + 0xEC) * i + outer_seed * outer_index) % 0x380) + 0x40
                y = ((inner_seed * i + (outer_index * outer_index * 0x4C + 0x1B) * outer_index) % 0x380) + 0x40
                entries.append(
                    spawn(
                        Vec2(float(x), float(y)),
                        heading=0.0,
                        spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_1D_FAST_07,
                        trigger_ms=trigger,
                        count=1,
                    )
                )
                trigger += 300
                inner_seed += 0x15
            trigger_base += 30000
        outer_seed += 0x35
        outer_index += 1
    return entries


@register_quest(
    level="4.9",
    title="The Annihilation",
    time_limit_ms=300000,
    start_weapon_id=1,
    unlock_perk_id=PerkId.BREATHING_ROOM,
    builder_address=0x004382C0,
)
def build_4_9_the_annihilation(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    half_w = ctx.width // 2
    entries.append(
        spawn(
            Vec2(128.0, float(half_w)),
            heading=0.0,
            spawn_id=SpawnId.ALIEN_CONST_RED_FAST_2B,
            trigger_ms=500,
            count=2,
        )
    )

    trigger = 500
    i_var5 = 0
    for idx in range(12):
        y = float(i_var5 // 12 + 0x80)
        x = 832.0 if idx % 2 == 0 else 896.0
        entries.append(
            spawn(Vec2(x, y), heading=0.0, spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_1D_FAST_07, trigger_ms=trigger, count=1)
        )
        trigger += 500
        i_var5 += 0x300

    trigger = 45000
    i_var5 = 0
    toggle = False
    for _ in range(12):
        y = float(i_var5 // 12 + 0x80)
        x = 832.0 if toggle else 896.0
        entries.append(
            spawn(Vec2(x, y), heading=0.0, spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_1D_FAST_07, trigger_ms=trigger, count=1)
        )
        trigger += 300
        toggle = not toggle
        i_var5 += 0x300
    return entries


@register_quest(
    level="4.10",
    title="The End of All",
    time_limit_ms=480000,
    start_weapon_id=1,
    unlock_weapon_id=0x17,
    builder_address=0x00438E10,
)
def build_4_10_the_end_of_all(ctx: QuestContext, full_version: bool = True) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = [
        spawn(
            Vec2(128.0, 128.0),
            heading=0.0,
            spawn_id=SpawnId.SPIDER_SP1_CONST_RANGED_VARIANT_3C,
            trigger_ms=3000,
            count=1,
        ),
        spawn(
            Vec2(896.0, 128.0),
            heading=0.0,
            spawn_id=SpawnId.SPIDER_SP1_CONST_RANGED_VARIANT_3C,
            trigger_ms=6000,
            count=1,
        ),
        spawn(
            Vec2(128.0, 896.0),
            heading=0.0,
            spawn_id=SpawnId.SPIDER_SP1_CONST_RANGED_VARIANT_3C,
            trigger_ms=9000,
            count=1,
        ),
        spawn(
            Vec2(896.0, 896.0),
            heading=0.0,
            spawn_id=SpawnId.SPIDER_SP1_CONST_RANGED_VARIANT_3C,
            trigger_ms=12000,
            count=1,
        ),
    ]

    center = center_point(ctx.width, ctx.height)
    edges_wide = edge_midpoints(ctx.width, ctx.height, offset=128.0)

    trigger = 13000
    for pos, _angle in ring_points(center, 80.0, 6, step=1.0471976):
        entries.append(
            spawn(
                pos,
                heading=0.0,
                spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_1D_FAST_07,
                trigger_ms=trigger,
                count=1,
            )
        )
        trigger += 300

    entries.append(
        spawn(
            Vec2(512.0, 512.0),
            heading=0.0,
            spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_3C_SLOW_0B,
            trigger_ms=trigger,
            count=1,
        )
    )

    trigger = 18000
    y = 0x100
    toggle = False
    while y < 0x300:
        x = edges_wide.right.x if toggle else edges_wide.left.x
        entries.append(
            spawn(
                Vec2(x, float(y)),
                heading=0.0,
                spawn_id=SpawnId.SPIDER_SP1_CONST_RANGED_VARIANT_3C,
                trigger_ms=trigger,
                count=2,
            )
        )
        trigger += 1000
        toggle = not toggle
        y += 0x80

    trigger = 43000
    for pos, _angle in ring_points(center, 80.0, 6, step=1.0471976, start=0.5235988):
        entries.append(
            spawn(
                pos,
                heading=0.0,
                spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_1D_FAST_07,
                trigger_ms=trigger,
                count=1,
            )
        )
        trigger += 300

    if full_version:
        trigger = 62800
        for pos, _angle in ring_points(center, 180.0, 12, step=0.5235988, start=0.5235988):
            entries.append(
                spawn(
                    pos,
                    heading=0.0,
                    spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_1D_FAST_07,
                    trigger_ms=trigger,
                    count=1,
                )
            )
            trigger += 500

    trigger = 48000
    y = 0x100
    toggle = False
    while y < 0x300:
        x = edges_wide.right.x if toggle else edges_wide.left.x
        entries.append(
            spawn(
                Vec2(x, float(y)),
                heading=0.0,
                spawn_id=SpawnId.SPIDER_SP1_CONST_RANGED_VARIANT_3C,
                trigger_ms=trigger,
                count=2,
            )
        )
        trigger += 1000
        toggle = not toggle
        y += 0x80

    return entries


__all__ = [
    "QuestContext",
    "SpawnEntry",
    "build_4_1_major_alien_breach",
    "build_4_2_zombie_time",
    "build_4_3_lizard_zombie_pact",
    "build_4_4_the_collaboration",
    "build_4_5_the_massacre",
    "build_4_6_the_unblitzkrieg",
    "build_4_7_gauntlet",
    "build_4_8_syntax_terror",
    "build_4_9_the_annihilation",
    "build_4_10_the_end_of_all",
]
