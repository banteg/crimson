from __future__ import annotations

from grim.geom import Vec2

from ..creatures.spawn import SpawnId
from ..rng_caller_static import RngCallerStatic
from ..sim.state_types import TERRAIN_SIZE
from .helpers import (
    NATIVE_CENTER,
    corner_points,
    edge_midpoints,
    heading_from_center,
    random_angle,
    ring_point,
    spawn,
)
from .types import QuestContext, SpawnEntry


def quest_build_land_hostile(_ctx: QuestContext) -> list[SpawnEntry]:
    edges = edge_midpoints()
    top_left, top_right, bottom_left, _bottom_right = corner_points()
    return [
        spawn(edges.bottom, SpawnId.ALIEN_SMALL_GRAY_26, 500, 1),
        spawn(bottom_left, SpawnId.ALIEN_SMALL_GRAY_26, 2500, 2),
        spawn(top_left, SpawnId.ALIEN_SMALL_GRAY_26, 6500, 3),
        spawn(top_right, SpawnId.ALIEN_SMALL_GRAY_26, 11500, 4),
    ]


def quest_build_minor_alien_breach(_ctx: QuestContext) -> list[SpawnEntry]:
    center = NATIVE_CENTER
    edges = edge_midpoints()
    entries = [
        spawn(Vec2(256.0, 256.0), SpawnId.ALIEN_SMALL_GRAY_26, 1000, 2),
        spawn(Vec2(256.0, 128.0), SpawnId.ALIEN_SMALL_GRAY_26, 1700, 2),
    ]
    for i in range(2, 18):
        trigger = (i * 5 - 10) * 720
        entries.append(spawn(edges.right, SpawnId.ALIEN_SMALL_GRAY_26, trigger, 1))
        if i > 6:
            entries.append(spawn(Vec2(edges.right.x, center.y - 256.0), SpawnId.ALIEN_SMALL_GRAY_26, trigger, 1))
        if i == 13:
            entries.append(spawn(edges.bottom, SpawnId.ALIEN_BIG_GRAY_29, 39600, 1))
        if i > 10:
            entries.append(spawn(Vec2(edges.left.x, center.y + 256.0), SpawnId.ALIEN_SMALL_GRAY_26, trigger, 1))
    return entries


def quest_build_target_practice(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    trigger = 2000
    step = 2000
    while True:
        angle = random_angle(ctx.rng.rand_tagged(RngCallerStatic.QUEST_BUILD_TARGET_PRACTICE_ANGLE))
        radius = (
            int(
                ctx.rng.rand_tagged(RngCallerStatic.QUEST_BUILD_TARGET_PRACTICE_RADIUS)
                % 8,
            )
            + 2
        ) * 32
        point = ring_point(NATIVE_CENTER, float(radius), angle)
        heading = heading_from_center(point, NATIVE_CENTER)
        entries.append(spawn(point, SpawnId.ALIEN_AI7_ORBITER_36, trigger, 1, heading=heading))
        trigger += max(step, 1100)
        step -= 50
        if step <= 500:
            break
    return entries


def quest_build_frontline_assault(_ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    edges = edge_midpoints()
    top_left, top_right, _bottom_left, _bottom_right = corner_points()
    step = 2500
    for i in range(2, 22):
        if i < 5:
            spawn_id = SpawnId.ALIEN_SMALL_GRAY_26
        elif i < 10:
            spawn_id = SpawnId.AI1_ALIEN_BLUE_TINT_1A
        else:
            spawn_id = SpawnId.ALIEN_SMALL_GRAY_26
        trigger = i * step - 5000
        entries.append(spawn(edges.bottom, spawn_id, trigger, 1))
        if i > 4:
            entries.append(spawn(top_left, SpawnId.ALIEN_SMALL_GRAY_26, trigger, 1))
        if i > 10:
            entries.append(spawn(top_right, SpawnId.ALIEN_SMALL_GRAY_26, trigger, 1))
        if i == 10:
            burst_trigger = (step * 5 - 2500) * 2
            entries.append(spawn(edges.right, SpawnId.ALIEN_BIG_GRAY_29, burst_trigger, 1))
            entries.append(spawn(edges.left, SpawnId.ALIEN_BIG_GRAY_29, burst_trigger, 1))
        step = max(step - 50, 1800)
    return entries


def quest_build_alien_dens(ctx: QuestContext) -> list[SpawnEntry]:
    return [
        spawn(Vec2(256.0, 256.0), SpawnId.DEN_ALIEN_BASIC_SLOWER_08, 1500, 1),
        spawn(Vec2(768.0, 768.0), SpawnId.DEN_ALIEN_BASIC_SLOWER_08, 1500, 1),
        spawn(Vec2(512.0, 512.0), SpawnId.DEN_ALIEN_BASIC_SLOWER_08, 23500, ctx.player_count),
        spawn(Vec2(256.0, 768.0), SpawnId.DEN_ALIEN_BASIC_SLOWER_08, 38500, 1),
        spawn(Vec2(768.0, 256.0), SpawnId.DEN_ALIEN_BASIC_SLOWER_08, 38500, 1),
    ]


def quest_build_the_random_factor(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    edges = edge_midpoints()
    trigger = 1500
    while trigger < 101500:
        entries.append(spawn(edges.right, SpawnId.ALIEN_RANDOM_1D, trigger, ctx.player_count * 2 + 4))
        entries.append(spawn(edges.left, SpawnId.ALIEN_RANDOM_1D, trigger + 200, 6))
        if (
            int(
                ctx.rng.rand_tagged(RngCallerStatic.QUEST_BUILD_THE_RANDOM_FACTOR_ALIEN_BIG_GRAY_GATE)
                % 5,
            )
            == 3
        ):
            entries.append(
                spawn(Vec2(edges.bottom.x, TERRAIN_SIZE + 64.0), SpawnId.ALIEN_BIG_GRAY_29, trigger, ctx.player_count),
            )
        trigger += 10000
    return entries


def quest_build_spider_wave_syndrome(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    edges = edge_midpoints()
    trigger = 1500
    while trigger < 100500:
        entries.append(spawn(edges.left, SpawnId.SPIDER_SMALL_BLUE_40, trigger, ctx.player_count * 2 + 6))
        trigger += 5500
    return entries


def quest_build_alien_squads(_ctx: QuestContext) -> list[SpawnEntry]:
    entries = [
        spawn(Vec2(-256.0, 256.0), SpawnId.FORMATION_RING_ALIEN_8_12, 1500, 1),
        spawn(Vec2(-256.0, 768.0), SpawnId.FORMATION_RING_ALIEN_8_12, 2500, 1),
        spawn(Vec2(768.0, -256.0), SpawnId.FORMATION_RING_ALIEN_8_12, 5500, 1),
        spawn(Vec2(768.0, 1280.0), SpawnId.FORMATION_RING_ALIEN_8_12, 8500, 1),
        spawn(Vec2(1280.0, 1280.0), SpawnId.FORMATION_RING_ALIEN_8_12, 14500, 1),
        spawn(Vec2(1280.0, 768.0), SpawnId.FORMATION_RING_ALIEN_8_12, 18500, 1),
        spawn(Vec2(-256.0, 256.0), SpawnId.FORMATION_RING_ALIEN_8_12, 25000, 1),
        spawn(Vec2(-256.0, 768.0), SpawnId.FORMATION_RING_ALIEN_8_12, 30000, 1),
    ]
    trigger = 36200
    while trigger < 83000:
        entries.append(spawn(Vec2(-64.0, -64.0), SpawnId.ALIEN_SMALL_GRAY_26, trigger - 400, 1))
        entries.append(spawn(Vec2(1088.0, 1088.0), SpawnId.ALIEN_SMALL_GRAY_26, trigger, 1))
        trigger += 1800
    return entries


def quest_build_nesting_grounds(ctx: QuestContext) -> list[SpawnEntry]:
    center = NATIVE_CENTER
    edges = edge_midpoints()
    return [
        spawn(Vec2(center.x, edges.bottom.y), SpawnId.ALIEN_RANDOM_1D, 1500, ctx.player_count * 2 + 6),
        spawn(Vec2(256.0, 256.0), SpawnId.DEN_ALIEN_WEAK_SMALL_09, 8000, 1),
        spawn(Vec2(512.0, 512.0), SpawnId.DEN_ALIEN_WEAK_SMALL_09, 13000, 1),
        spawn(Vec2(768.0, 768.0), SpawnId.DEN_ALIEN_WEAK_SMALL_09, 18000, 1),
        spawn(Vec2(center.x, edges.bottom.y), SpawnId.ALIEN_RANDOM_1D, 25000, ctx.player_count * 2 + 6),
        spawn(Vec2(center.x, edges.bottom.y), SpawnId.ALIEN_RANDOM_1D, 39000, ctx.player_count * 3 + 3),
        spawn(Vec2(384.0, 512.0), SpawnId.DEN_ALIEN_WEAK_SMALL_09, 41100, 1),
        spawn(Vec2(640.0, 512.0), SpawnId.DEN_ALIEN_WEAK_SMALL_09, 42100, 1),
        spawn(Vec2(512.0, 640.0), SpawnId.DEN_ALIEN_WEAK_SMALL_09, 43100, 1),
        spawn(Vec2(512.0, 512.0), SpawnId.DEN_ALIEN_BASIC_SLOWER_08, 44100, 1),
        spawn(Vec2(center.x, edges.bottom.y), SpawnId.ALIEN_RANDOM_1E, 50000, ctx.player_count * 2 + 5),
        spawn(Vec2(center.x, edges.bottom.y), SpawnId.ALIEN_RANDOM_1F, 55000, ctx.player_count * 2 + 2),
    ]


def quest_build_8_legged_terror(ctx: QuestContext) -> list[SpawnEntry]:
    entries = [
        spawn(Vec2(float(TERRAIN_SIZE - 256), float(TERRAIN_SIZE // 2)), SpawnId.SPIDER_BOSS_3A, 1000, 1),
    ]
    top_left, top_right, bottom_left, bottom_right = corner_points(offset=25.0)
    trigger = 6000
    while trigger < 36800:
        entries.append(spawn(top_left, SpawnId.SPIDER_SP1_RANDOM_3D, trigger, ctx.player_count))
        entries.append(spawn(top_right, SpawnId.SPIDER_SP1_RANDOM_3D, trigger, 1))
        entries.append(spawn(bottom_left, SpawnId.SPIDER_SP1_RANDOM_3D, trigger, ctx.player_count))
        entries.append(spawn(bottom_right, SpawnId.SPIDER_SP1_RANDOM_3D, trigger, 1))
        trigger += 2200
    return entries


__all__ = [
    "QuestContext",
    "SpawnEntry",
    "quest_build_8_legged_terror",
    "quest_build_alien_dens",
    "quest_build_alien_squads",
    "quest_build_frontline_assault",
    "quest_build_land_hostile",
    "quest_build_minor_alien_breach",
    "quest_build_nesting_grounds",
    "quest_build_spider_wave_syndrome",
    "quest_build_target_practice",
    "quest_build_the_random_factor",
]
