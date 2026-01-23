from __future__ import annotations

import math
import random

from ..perks import PerkId
from .helpers import center_point, corner_points, edge_midpoints, heading_from_center, random_angle
from .registry import register_quest
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


@register_quest(
    level="1.1",
    title="Land Hostile",
    time_limit_ms=120000,
    start_weapon_id=1,
    unlock_weapon_id=0x02,
    builder_address=0x00435bd0,
)
def build_1_1_land_hostile(ctx: QuestContext) -> list[SpawnEntry]:
    edges = edge_midpoints(ctx.width, ctx.height)
    top_left, top_right, bottom_left, _bottom_right = corner_points(ctx.width, ctx.height)
    return [
        SpawnEntry(*edges.bottom, 0.0, SPAWN_ID_38, 500, 1),
        SpawnEntry(*bottom_left, 0.0, SPAWN_ID_38, 2500, 2),
        SpawnEntry(*top_left, 0.0, SPAWN_ID_38, 6500, 3),
        SpawnEntry(*top_right, 0.0, SPAWN_ID_38, 11500, 4),
    ]


@register_quest(
    level="1.2",
    title="Minor Alien Breach",
    time_limit_ms=120000,
    start_weapon_id=1,
    unlock_weapon_id=0x03,
    builder_address=0x00435cc0,
)
def build_1_2_minor_alien_breach(ctx: QuestContext) -> list[SpawnEntry]:
    center_x, center_y = center_point(ctx.width, ctx.height)
    edges = edge_midpoints(ctx.width, ctx.height)
    entries = [
        SpawnEntry(256.0, 256.0, 0.0, SPAWN_ID_38, 1000, 2),
        SpawnEntry(256.0, 128.0, 0.0, SPAWN_ID_38, 1700, 2),
    ]
    for i in range(2, 18):
        trigger = (i * 5 - 10) * 720
        entries.append(SpawnEntry(*edges.right, 0.0, SPAWN_ID_38, trigger, 1))
        if i > 6:
            entries.append(
                SpawnEntry(edges.right[0], center_y - 256.0, 0.0, SPAWN_ID_38, trigger, 1)
            )
        if i == 13:
            entries.append(
                SpawnEntry(*edges.bottom, 0.0, SPAWN_ID_41, 39600, 1)
            )
        if i > 10:
            entries.append(
                SpawnEntry(edges.left[0], center_y + 256.0, 0.0, SPAWN_ID_38, trigger, 1)
            )
    return entries


@register_quest(
    level="1.3",
    title="Target Practice",
    time_limit_ms=65000,
    start_weapon_id=1,
    unlock_perk_id=PerkId.URANIUM_FILLED_BULLETS,
    builder_address=0x00437a00,
)
def build_1_3_target_practice(
    ctx: QuestContext, rng: random.Random | None = None
) -> list[SpawnEntry]:
    rng = rng or random.Random()
    center_x, center_y = center_point(ctx.width, ctx.height)
    entries: list[SpawnEntry] = []
    trigger = 2000
    step = 2000
    while True:
        angle = random_angle(rng)
        radius = (rng.randrange(8) + 2) * 0x20
        x = math.cos(angle) * radius + center_x
        y = math.sin(angle) * radius + center_y
        heading = heading_from_center(x, y, center_x, center_y)
        entries.append(SpawnEntry(x, y, heading, SPAWN_ID_54, trigger, 1))
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
    builder_address=0x00437e10,
)
def build_1_4_frontline_assault(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    edges = edge_midpoints(ctx.width, ctx.height)
    top_left, top_right, _bottom_left, _bottom_right = corner_points(ctx.width, ctx.height)
    step = 2500
    for i in range(2, 22):
        if i < 5:
            spawn_id = SPAWN_ID_38
        elif i < 10:
            spawn_id = SPAWN_ID_26
        else:
            spawn_id = SPAWN_ID_38
        trigger = i * step - 5000
        entries.append(SpawnEntry(*edges.bottom, 0.0, spawn_id, trigger, 1))
        if i > 4:
            entries.append(SpawnEntry(*top_left, 0.0, SPAWN_ID_38, trigger, 1))
        if i > 10:
            entries.append(SpawnEntry(*top_right, 0.0, SPAWN_ID_38, trigger, 1))
        if i == 10:
            burst_trigger = (step * 5 - 2500) * 2
            entries.append(SpawnEntry(*edges.right, 0.0, SPAWN_ID_41, burst_trigger, 1))
            entries.append(SpawnEntry(*edges.left, 0.0, SPAWN_ID_41, burst_trigger, 1))
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
        SpawnEntry(256.0, 256.0, 0.0, SPAWN_ID_8, 1500, 1),
        SpawnEntry(768.0, 768.0, 0.0, SPAWN_ID_8, 1500, 1),
        SpawnEntry(512.0, 512.0, 0.0, SPAWN_ID_8, 23500, ctx.player_count),
        SpawnEntry(256.0, 768.0, 0.0, SPAWN_ID_8, 38500, 1),
        SpawnEntry(768.0, 256.0, 0.0, SPAWN_ID_8, 38500, 1),
    ]


@register_quest(
    level="1.6",
    title="The Random Factor",
    time_limit_ms=300000,
    start_weapon_id=1,
    unlock_weapon_id=0x05,
    builder_address=0x00436350,
)
def build_1_6_the_random_factor(
    ctx: QuestContext, rng: random.Random | None = None
) -> list[SpawnEntry]:
    rng = rng or random.Random()
    entries: list[SpawnEntry] = []
    center_x, center_y = center_point(ctx.width, ctx.height)
    edges = edge_midpoints(ctx.width, ctx.height)
    trigger = 1500
    while trigger < 101500:
        entries.append(
            SpawnEntry(*edges.right, 0.0, SPAWN_ID_29, trigger, ctx.player_count * 2 + 4)
        )
        entries.append(
            SpawnEntry(*edges.left, 0.0, SPAWN_ID_29, trigger + 200, 6)
        )
        if rng.randrange(5) == 3:
            entries.append(
                SpawnEntry(
                    center_x,
                    edges.bottom[1],
                    0.0,
                    SPAWN_ID_41,
                    trigger,
                    ctx.player_count,
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
            SpawnEntry(*edges.left, 0.0, SPAWN_ID_64, trigger, ctx.player_count * 2 + 6)
        )
        trigger += 5500
    return entries


@register_quest(
    level="1.8",
    title="Alien Squads",
    time_limit_ms=180000,
    start_weapon_id=1,
    unlock_weapon_id=0x06,
    builder_address=0x00435ea0,
)
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


@register_quest(
    level="1.9",
    title="Nesting Grounds",
    time_limit_ms=240000,
    start_weapon_id=1,
    unlock_perk_id=PerkId.HOT_TEMPERED,
    builder_address=0x004364a0,
)
def build_1_9_nesting_grounds(ctx: QuestContext) -> list[SpawnEntry]:
    center_x, _center_y = center_point(ctx.width, ctx.height)
    edges = edge_midpoints(ctx.width, ctx.height)
    entries = [
        SpawnEntry(center_x, edges.bottom[1], 0.0, SPAWN_ID_29, 1500, ctx.player_count * 2 + 6),
        SpawnEntry(256.0, 256.0, 0.0, SPAWN_ID_9, 8000, 1),
        SpawnEntry(512.0, 512.0, 0.0, SPAWN_ID_9, 13000, 1),
        SpawnEntry(768.0, 768.0, 0.0, SPAWN_ID_9, 18000, 1),
        SpawnEntry(center_x, edges.bottom[1], 0.0, SPAWN_ID_29, 25000, ctx.player_count * 2 + 6),
        SpawnEntry(center_x, edges.bottom[1], 0.0, SPAWN_ID_29, 39000, ctx.player_count * 3 + 3),
        SpawnEntry(384.0, 512.0, 0.0, SPAWN_ID_9, 41100, 1),
        SpawnEntry(640.0, 512.0, 0.0, SPAWN_ID_9, 42100, 1),
        SpawnEntry(512.0, 640.0, 0.0, SPAWN_ID_9, 43100, 1),
        SpawnEntry(512.0, 512.0, 0.0, SPAWN_ID_8, 44100, 1),
        SpawnEntry(center_x, edges.bottom[1], 0.0, SPAWN_ID_30, 50000, ctx.player_count * 2 + 5),
        SpawnEntry(center_x, edges.bottom[1], 0.0, SPAWN_ID_31, 55000, ctx.player_count * 2 + 2),
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
        SpawnEntry(float(ctx.width - 256), float(ctx.width // 2), 0.0, SPAWN_ID_58, 1000, 1)
    ]
    top_left, top_right, bottom_left, bottom_right = corner_points(
        ctx.width, ctx.height, offset=25.0
    )
    trigger = 6000
    while trigger < 36800:
        entries.append(
            SpawnEntry(*top_left, 0.0, SPAWN_ID_61, trigger, ctx.player_count)
        )
        entries.append(
            SpawnEntry(*top_right, 0.0, SPAWN_ID_61, trigger, 1)
        )
        entries.append(
            SpawnEntry(*bottom_left, 0.0, SPAWN_ID_61, trigger, ctx.player_count)
        )
        entries.append(
            SpawnEntry(*bottom_right, 0.0, SPAWN_ID_61, trigger, 1)
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
