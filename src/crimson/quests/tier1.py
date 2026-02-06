from __future__ import annotations

import random

from grim.geom import Vec2

from ..perks import PerkId
from ..creatures.spawn import SpawnId
from .helpers import (
    center_point,
    corner_points,
    edge_midpoints,
    heading_from_center,
    random_angle,
    spawn,
    spawn_at,
)
from .registry import register_quest
from .types import QuestContext, SpawnEntry


@register_quest(
    level="1.1",
    title="Land Hostile",
    time_limit_ms=120000,
    start_weapon_id=1,
    unlock_weapon_id=0x02,
    builder_address=0x00435BD0,
)
def build_1_1_land_hostile(ctx: QuestContext) -> list[SpawnEntry]:
    edges = edge_midpoints(ctx.width, ctx.height)
    top_left, top_right, bottom_left, _bottom_right = corner_points(ctx.width, ctx.height)
    return [
        spawn_at(edges.bottom, heading=0.0, spawn_id=SpawnId.ALIEN_CONST_PALE_GREEN_26, trigger_ms=500, count=1),
        spawn_at(bottom_left, heading=0.0, spawn_id=SpawnId.ALIEN_CONST_PALE_GREEN_26, trigger_ms=2500, count=2),
        spawn_at(top_left, heading=0.0, spawn_id=SpawnId.ALIEN_CONST_PALE_GREEN_26, trigger_ms=6500, count=3),
        spawn_at(top_right, heading=0.0, spawn_id=SpawnId.ALIEN_CONST_PALE_GREEN_26, trigger_ms=11500, count=4),
    ]


@register_quest(
    level="1.2",
    title="Minor Alien Breach",
    time_limit_ms=120000,
    start_weapon_id=1,
    unlock_weapon_id=0x03,
    builder_address=0x00435CC0,
)
def build_1_2_minor_alien_breach(ctx: QuestContext) -> list[SpawnEntry]:
    center = center_point(ctx.width, ctx.height)
    edges = edge_midpoints(ctx.width, ctx.height)
    entries = [
        spawn(
            x=256.0,
            y=256.0,
            heading=0.0,
            spawn_id=SpawnId.ALIEN_CONST_PALE_GREEN_26,
            trigger_ms=1000,
            count=2,
        ),
        spawn(
            x=256.0,
            y=128.0,
            heading=0.0,
            spawn_id=SpawnId.ALIEN_CONST_PALE_GREEN_26,
            trigger_ms=1700,
            count=2,
        ),
    ]
    for i in range(2, 18):
        trigger = (i * 5 - 10) * 720
        entries.append(
            spawn_at(
                edges.right,
                heading=0.0,
                spawn_id=SpawnId.ALIEN_CONST_PALE_GREEN_26,
                trigger_ms=trigger,
                count=1,
            )
        )
        if i > 6:
            entries.append(
                spawn(
                    x=edges.right.x,
                    y=center.y - 256.0,
                    heading=0.0,
                    spawn_id=SpawnId.ALIEN_CONST_PALE_GREEN_26,
                    trigger_ms=trigger,
                    count=1,
                )
            )
        if i == 13:
            entries.append(
                spawn_at(
                    edges.bottom,
                    heading=0.0,
                    spawn_id=SpawnId.ALIEN_CONST_GREY_BRUTE_29,
                    trigger_ms=39600,
                    count=1,
                )
            )
        if i > 10:
            entries.append(
                spawn(
                    x=edges.left.x,
                    y=center.y + 256.0,
                    heading=0.0,
                    spawn_id=SpawnId.ALIEN_CONST_PALE_GREEN_26,
                    trigger_ms=trigger,
                    count=1,
                )
            )
    return entries


@register_quest(
    level="1.3",
    title="Target Practice",
    time_limit_ms=65000,
    start_weapon_id=1,
    unlock_perk_id=PerkId.URANIUM_FILLED_BULLETS,
    builder_address=0x00437A00,
)
def build_1_3_target_practice(ctx: QuestContext, rng: random.Random | None = None) -> list[SpawnEntry]:
    rng = rng or random.Random()
    center = center_point(ctx.width, ctx.height)
    entries: list[SpawnEntry] = []
    trigger = 2000
    step = 2000
    while True:
        angle = random_angle(rng)
        radius = (rng.randrange(8) + 2) * 0x20
        point = center + Vec2.from_angle(angle) * radius
        heading = heading_from_center(point, center)
        entries.append(
            spawn(
                x=point.x,
                y=point.y,
                heading=heading,
                spawn_id=SpawnId.ALIEN_AI7_ORBITER_36,
                trigger_ms=trigger,
                count=1,
            )
        )
        trigger += max(step, 1100)
        step -= 50
        if step <= 500:
            break
    return entries


@register_quest(
    level="1.4",
    title="Frontline Assault",
    time_limit_ms=300000,
    start_weapon_id=1,
    unlock_weapon_id=0x08,
    builder_address=0x00437E10,
)
def build_1_4_frontline_assault(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    edges = edge_midpoints(ctx.width, ctx.height)
    top_left, top_right, _bottom_left, _bottom_right = corner_points(ctx.width, ctx.height)
    step = 2500
    for i in range(2, 22):
        if i < 5:
            spawn_id = SpawnId.ALIEN_CONST_PALE_GREEN_26
        elif i < 10:
            spawn_id = SpawnId.AI1_ALIEN_BLUE_TINT_1A
        else:
            spawn_id = SpawnId.ALIEN_CONST_PALE_GREEN_26
        trigger = i * step - 5000
        entries.append(
            spawn_at(
                edges.bottom,
                heading=0.0,
                spawn_id=spawn_id,
                trigger_ms=trigger,
                count=1,
            )
        )
        if i > 4:
            entries.append(
                spawn_at(
                    top_left,
                    heading=0.0,
                    spawn_id=SpawnId.ALIEN_CONST_PALE_GREEN_26,
                    trigger_ms=trigger,
                    count=1,
                )
            )
        if i > 10:
            entries.append(
                spawn_at(
                    top_right,
                    heading=0.0,
                    spawn_id=SpawnId.ALIEN_CONST_PALE_GREEN_26,
                    trigger_ms=trigger,
                    count=1,
                )
            )
        if i == 10:
            burst_trigger = (step * 5 - 2500) * 2
            entries.append(
                spawn_at(
                    edges.right,
                    heading=0.0,
                    spawn_id=SpawnId.ALIEN_CONST_GREY_BRUTE_29,
                    trigger_ms=burst_trigger,
                    count=1,
                )
            )
            entries.append(
                spawn_at(
                    edges.left,
                    heading=0.0,
                    spawn_id=SpawnId.ALIEN_CONST_GREY_BRUTE_29,
                    trigger_ms=burst_trigger,
                    count=1,
                )
            )
        step = max(step - 50, 1800)
    return entries


@register_quest(
    level="1.5",
    title="Alien Dens",
    time_limit_ms=180000,
    start_weapon_id=1,
    unlock_perk_id=PerkId.DOCTOR,
    builder_address=0x00436720,
)
def build_1_5_alien_dens(ctx: QuestContext) -> list[SpawnEntry]:
    return [
        spawn(x=256.0, y=256.0, heading=0.0, spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_1D_SLOW_08, trigger_ms=1500, count=1),
        spawn(x=768.0, y=768.0, heading=0.0, spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_1D_SLOW_08, trigger_ms=1500, count=1),
        spawn(
            x=512.0,
            y=512.0,
            heading=0.0,
            spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_1D_SLOW_08,
            trigger_ms=23500,
            count=ctx.player_count,
        ),
        spawn(
            x=256.0,
            y=768.0,
            heading=0.0,
            spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_1D_SLOW_08,
            trigger_ms=38500,
            count=1,
        ),
        spawn(
            x=768.0,
            y=256.0,
            heading=0.0,
            spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_1D_SLOW_08,
            trigger_ms=38500,
            count=1,
        ),
    ]


@register_quest(
    level="1.6",
    title="The Random Factor",
    time_limit_ms=300000,
    start_weapon_id=1,
    unlock_weapon_id=0x05,
    builder_address=0x00436350,
)
def build_1_6_the_random_factor(ctx: QuestContext, rng: random.Random | None = None) -> list[SpawnEntry]:
    rng = rng or random.Random()
    entries: list[SpawnEntry] = []
    center = center_point(ctx.width, ctx.height)
    edges = edge_midpoints(ctx.width, ctx.height)
    trigger = 1500
    while trigger < 101500:
        entries.append(
            spawn_at(
                edges.right,
                heading=0.0,
                spawn_id=SpawnId.ALIEN_RANDOM_1D,
                trigger_ms=trigger,
                count=ctx.player_count * 2 + 4,
            )
        )
        entries.append(
            spawn_at(
                edges.left,
                heading=0.0,
                spawn_id=SpawnId.ALIEN_RANDOM_1D,
                trigger_ms=trigger + 200,
                count=6,
            )
        )
        if rng.randrange(5) == 3:
            entries.append(
                spawn(
                    x=center.x,
                    y=edges.bottom.y,
                    heading=0.0,
                    spawn_id=SpawnId.ALIEN_CONST_GREY_BRUTE_29,
                    trigger_ms=trigger,
                    count=ctx.player_count,
                )
            )
        trigger += 10000
    return entries


@register_quest(
    level="1.7",
    title="Spider Wave Syndrome",
    time_limit_ms=240000,
    start_weapon_id=1,
    unlock_perk_id=PerkId.MONSTER_VISION,
    builder_address=0x00436440,
)
def build_1_7_spider_wave_syndrome(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    edges = edge_midpoints(ctx.width, ctx.height)
    trigger = 1500
    while trigger < 100500:
        entries.append(
            spawn_at(
                edges.left,
                heading=0.0,
                spawn_id=SpawnId.SPIDER_SP1_CONST_BLUE_40,
                trigger_ms=trigger,
                count=ctx.player_count * 2 + 6,
            )
        )
        trigger += 5500
    return entries


@register_quest(
    level="1.8",
    title="Alien Squads",
    time_limit_ms=180000,
    start_weapon_id=1,
    unlock_weapon_id=0x06,
    builder_address=0x00435EA0,
)
def build_1_8_alien_squads(ctx: QuestContext) -> list[SpawnEntry]:
    entries = [
        spawn(
            x=-256.0,
            y=256.0,
            heading=0.0,
            spawn_id=SpawnId.FORMATION_RING_ALIEN_8_12,
            trigger_ms=1500,
            count=1,
        ),
        spawn(
            x=-256.0,
            y=768.0,
            heading=0.0,
            spawn_id=SpawnId.FORMATION_RING_ALIEN_8_12,
            trigger_ms=2500,
            count=1,
        ),
        spawn(
            x=768.0,
            y=-256.0,
            heading=0.0,
            spawn_id=SpawnId.FORMATION_RING_ALIEN_8_12,
            trigger_ms=5500,
            count=1,
        ),
        spawn(
            x=768.0,
            y=1280.0,
            heading=0.0,
            spawn_id=SpawnId.FORMATION_RING_ALIEN_8_12,
            trigger_ms=8500,
            count=1,
        ),
        spawn(
            x=1280.0,
            y=1280.0,
            heading=0.0,
            spawn_id=SpawnId.FORMATION_RING_ALIEN_8_12,
            trigger_ms=14500,
            count=1,
        ),
        spawn(
            x=1280.0,
            y=768.0,
            heading=0.0,
            spawn_id=SpawnId.FORMATION_RING_ALIEN_8_12,
            trigger_ms=18500,
            count=1,
        ),
        spawn(
            x=-256.0,
            y=256.0,
            heading=0.0,
            spawn_id=SpawnId.FORMATION_RING_ALIEN_8_12,
            trigger_ms=25000,
            count=1,
        ),
        spawn(
            x=-256.0,
            y=768.0,
            heading=0.0,
            spawn_id=SpawnId.FORMATION_RING_ALIEN_8_12,
            trigger_ms=30000,
            count=1,
        ),
    ]
    trigger = 36200
    while trigger < 83000:
        entries.append(
            spawn(
                x=-64.0,
                y=-64.0,
                heading=0.0,
                spawn_id=SpawnId.ALIEN_CONST_PALE_GREEN_26,
                trigger_ms=trigger - 400,
                count=1,
            )
        )
        entries.append(
            spawn(
                x=ctx.width + 64.0,
                y=ctx.height + 64.0,
                heading=0.0,
                spawn_id=SpawnId.ALIEN_CONST_PALE_GREEN_26,
                trigger_ms=trigger,
                count=1,
            )
        )
        trigger += 1800
    return entries


@register_quest(
    level="1.9",
    title="Nesting Grounds",
    time_limit_ms=240000,
    start_weapon_id=1,
    unlock_perk_id=PerkId.HOT_TEMPERED,
    builder_address=0x004364A0,
)
def build_1_9_nesting_grounds(ctx: QuestContext) -> list[SpawnEntry]:
    center = center_point(ctx.width, ctx.height)
    edges = edge_midpoints(ctx.width, ctx.height)
    entries = [
        spawn(
            x=center.x,
            y=edges.bottom.y,
            heading=0.0,
            spawn_id=SpawnId.ALIEN_RANDOM_1D,
            trigger_ms=1500,
            count=ctx.player_count * 2 + 6,
        ),
        spawn(x=256.0, y=256.0, heading=0.0, spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_1D_LIMITED_09, trigger_ms=8000, count=1),
        spawn(
            x=512.0,
            y=512.0,
            heading=0.0,
            spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_1D_LIMITED_09,
            trigger_ms=13000,
            count=1,
        ),
        spawn(
            x=768.0,
            y=768.0,
            heading=0.0,
            spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_1D_LIMITED_09,
            trigger_ms=18000,
            count=1,
        ),
        spawn(
            x=center.x,
            y=edges.bottom.y,
            heading=0.0,
            spawn_id=SpawnId.ALIEN_RANDOM_1D,
            trigger_ms=25000,
            count=ctx.player_count * 2 + 6,
        ),
        spawn(
            x=center.x,
            y=edges.bottom.y,
            heading=0.0,
            spawn_id=SpawnId.ALIEN_RANDOM_1D,
            trigger_ms=39000,
            count=ctx.player_count * 3 + 3,
        ),
        spawn(
            x=384.0,
            y=512.0,
            heading=0.0,
            spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_1D_LIMITED_09,
            trigger_ms=41100,
            count=1,
        ),
        spawn(
            x=640.0,
            y=512.0,
            heading=0.0,
            spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_1D_LIMITED_09,
            trigger_ms=42100,
            count=1,
        ),
        spawn(
            x=512.0,
            y=640.0,
            heading=0.0,
            spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_1D_LIMITED_09,
            trigger_ms=43100,
            count=1,
        ),
        spawn(
            x=512.0,
            y=512.0,
            heading=0.0,
            spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_1D_SLOW_08,
            trigger_ms=44100,
            count=1,
        ),
        spawn(
            x=center.x,
            y=edges.bottom.y,
            heading=0.0,
            spawn_id=SpawnId.ALIEN_RANDOM_1E,
            trigger_ms=50000,
            count=ctx.player_count * 2 + 5,
        ),
        spawn(
            x=center.x,
            y=edges.bottom.y,
            heading=0.0,
            spawn_id=SpawnId.ALIEN_RANDOM_1F,
            trigger_ms=55000,
            count=ctx.player_count * 2 + 2,
        ),
    ]
    return entries


@register_quest(
    level="1.10",
    title="8-legged Terror",
    time_limit_ms=240000,
    start_weapon_id=1,
    unlock_weapon_id=0x0C,
    builder_address=0x00436120,
)
def build_1_10_8_legged_terror(ctx: QuestContext) -> list[SpawnEntry]:
    entries = [
        spawn(
            x=float(ctx.width - 256),
            y=float(ctx.width // 2),
            heading=0.0,
            spawn_id=SpawnId.SPIDER_SP1_CONST_SHOCK_BOSS_3A,
            trigger_ms=1000,
            count=1,
        )
    ]
    top_left, top_right, bottom_left, bottom_right = corner_points(ctx.width, ctx.height, offset=25.0)
    trigger = 6000
    while trigger < 36800:
        entries.append(
            spawn_at(
                top_left,
                heading=0.0,
                spawn_id=SpawnId.SPIDER_SP1_RANDOM_3D,
                trigger_ms=trigger,
                count=ctx.player_count,
            )
        )
        entries.append(
            spawn_at(
                top_right,
                heading=0.0,
                spawn_id=SpawnId.SPIDER_SP1_RANDOM_3D,
                trigger_ms=trigger,
                count=1,
            )
        )
        entries.append(
            spawn_at(
                bottom_left,
                heading=0.0,
                spawn_id=SpawnId.SPIDER_SP1_RANDOM_3D,
                trigger_ms=trigger,
                count=ctx.player_count,
            )
        )
        entries.append(
            spawn_at(
                bottom_right,
                heading=0.0,
                spawn_id=SpawnId.SPIDER_SP1_RANDOM_3D,
                trigger_ms=trigger,
                count=1,
            )
        )
        trigger += 2200
    return entries


__all__ = [
    "QuestContext",
    "SpawnEntry",
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
