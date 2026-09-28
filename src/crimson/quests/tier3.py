from __future__ import annotations

from grim.geom import Vec2
from grim.rand import CrandLike

from ..creatures.spawn import SpawnId
from ..math_parity import f32, x87_pc24_add, x87_pc24_mul
from ..rng_caller_static import RngCallerStatic
from ..sim.state_types import TERRAIN_SIZE
from .helpers import (
    NATIVE_CENTER,
    edge_midpoints,
    radial_points,
    random_angle,
    ring_points,
    spawn,
)
from .types import QuestContext, SpawnEntry


def quest_build_the_blighting(_ctx: QuestContext) -> list[SpawnEntry]:
    edges = edge_midpoints()
    edges_wide = edge_midpoints(offset=128.0)
    entries = [
        spawn(edges_wide.right, SpawnId.ALIEN_DEADLY_FAST_2B, 1500, 2),
        spawn(edges_wide.left, SpawnId.ALIEN_DEADLY_FAST_2B, 1500, 2),
        spawn(Vec2(896.0, 128.0), SpawnId.DEN_ALIEN_BASIC_07, 2000, 1),
        spawn(Vec2(128.0, 128.0), SpawnId.DEN_ALIEN_BASIC_07, 2000, 1),
        spawn(Vec2(128.0, 896.0), SpawnId.DEN_ALIEN_BASIC_07, 2000, 1),
        spawn(Vec2(896.0, 896.0), SpawnId.DEN_ALIEN_BASIC_07, 2000, 1),
    ]

    trigger = 4000
    for wave in range(8):
        if wave in (2, 4):
            entries.append(spawn(edges_wide.left, SpawnId.ALIEN_DEADLY_FAST_2B, trigger, 4))
        if wave in (3, 5):
            entries.append(spawn(Vec2(1152.0, edges_wide.right.y), SpawnId.ALIEN_DEADLY_FAST_2B, trigger, 4))
        spawn_id = SpawnId.AI1_ALIEN_BLUE_TINT_1A if wave % 2 == 0 else SpawnId.AI1_LIZARD_BLUE_TINT_1C
        edge = wave % 5
        if edge == 0:
            entries.append(spawn(edges.right, spawn_id, trigger, 12))
            trigger += 15000
        elif edge == 1:
            entries.append(spawn(edges.left, spawn_id, trigger, 12))
            trigger += 15000
        elif edge == 2:
            entries.append(spawn(edges.bottom, spawn_id, trigger, 12))
            trigger += 15000
        elif edge == 3:
            entries.append(spawn(edges.top, spawn_id, trigger, 12))
            trigger += 15000
        trigger += 1000
    return entries


def quest_build_lizard_kings(_ctx: QuestContext) -> list[SpawnEntry]:
    entries = [
        spawn(Vec2(1152.0, 512.0), SpawnId.FORMATION_CHAIN_LIZARD_4_11, 1500, 1),
        spawn(Vec2(-128.0, 512.0), SpawnId.FORMATION_CHAIN_LIZARD_4_11, 1500, 1),
        spawn(Vec2(1152.0, 896.0), SpawnId.FORMATION_CHAIN_LIZARD_4_11, 1500, 1),
    ]
    trigger = 1500
    for pos, angle in ring_points(NATIVE_CENTER, 256.0, 28, step=0.34906587):
        entries.append(spawn(pos, SpawnId.LIZARD_RANDOM_31, trigger, 1, heading=-angle))
        trigger += 900
    return entries


def _the_killing_random_spawner(
    *,
    rng: CrandLike,
    trigger_ms: int,
    y_caller: int,
    x_caller: int,
) -> SpawnEntry:
    y = float(rng.rand_tagged(y_caller) % 768) + 128.0
    x = float(rng.rand_tagged(x_caller) % 768) + 128.0
    return spawn(Vec2(x, y), SpawnId.DEN_ALIEN_BASIC_07, trigger_ms, 3)


def quest_build_the_killing(ctx: QuestContext) -> list[SpawnEntry]:
    edges = edge_midpoints()
    entries: list[SpawnEntry] = []
    trigger = 2000
    for wave in range(10):
        # Native bug (0x4384a0): both picks roll `crt_rand()` but discard the
        # result and branch on the wave counter, so the wave layout is a fixed
        # cycle while the rng stream still advances two draws per wave.
        ctx.rng.rand_tagged(RngCallerStatic.QUEST_BUILD_THE_KILLING_TEMPLATE_PICK)
        spawn_cycle = wave % 3
        if spawn_cycle == 0:
            spawn_id = SpawnId.AI1_ALIEN_BLUE_TINT_1A
        elif spawn_cycle == 1:
            spawn_id = SpawnId.AI1_SPIDER_SP1_BLUE_TINT_1B
        else:
            spawn_id = SpawnId.AI1_LIZARD_BLUE_TINT_1C

        ctx.rng.rand_tagged(RngCallerStatic.QUEST_BUILD_THE_KILLING_LAYOUT_PICK)
        edge = wave % 5
        if edge == 0:
            entries.append(spawn(edges.right, spawn_id, trigger, 12))
        elif edge == 1:
            entries.append(spawn(edges.left, spawn_id, trigger, 12))
        elif edge == 2:
            entries.append(spawn(edges.bottom, spawn_id, trigger, 12))
        elif edge == 3:
            entries.append(spawn(edges.top, spawn_id, trigger, 12))
        else:
            entries.append(
                _the_killing_random_spawner(
                    rng=ctx.rng,
                    trigger_ms=trigger,
                    y_caller=RngCallerStatic.QUEST_BUILD_THE_KILLING_SPAWNER_1_Y,
                    x_caller=RngCallerStatic.QUEST_BUILD_THE_KILLING_SPAWNER_1_X,
                ),
            )
            entries.append(
                _the_killing_random_spawner(
                    rng=ctx.rng,
                    trigger_ms=trigger + 1000,
                    y_caller=RngCallerStatic.QUEST_BUILD_THE_KILLING_SPAWNER_2_Y,
                    x_caller=RngCallerStatic.QUEST_BUILD_THE_KILLING_SPAWNER_2_X,
                ),
            )
            entries.append(
                _the_killing_random_spawner(
                    rng=ctx.rng,
                    trigger_ms=trigger + 2000,
                    y_caller=RngCallerStatic.QUEST_BUILD_THE_KILLING_SPAWNER_3_Y,
                    x_caller=RngCallerStatic.QUEST_BUILD_THE_KILLING_SPAWNER_3_X,
                ),
            )

        trigger += 6000
    return entries


def quest_build_hidden_evil(_ctx: QuestContext) -> list[SpawnEntry]:
    edges = edge_midpoints()
    return [
        spawn(edges.bottom, SpawnId.ALIEN_HIDDEN_1_21, 500, 50),
        spawn(edges.bottom, SpawnId.ALIEN_HIDDEN_2_22, 15000, 30),
        spawn(edges.bottom, SpawnId.ALIEN_HIDDEN_3_23, 25000, 20),
        spawn(edges.bottom, SpawnId.ALIEN_HIDDEN_3_23, 30000, 30),
        spawn(edges.bottom, SpawnId.ALIEN_HIDDEN_2_22, 35000, 30),
    ]


def _surrounded_by_reptiles_axes() -> list[float]:
    # `(float)line_offset * 0.2f + 256.0f` for line_offset = 0, 512, ... 2048.
    return [x87_pc24_add(x87_pc24_mul(float(offset), f32(0.2)), 256.0) for offset in range(0, 5 * 512, 512)]


def quest_build_surrounded_by_reptiles(_ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    trigger = 1000
    for axis in _surrounded_by_reptiles_axes():
        entries.append(spawn(Vec2(256.0, axis), SpawnId.DEN_LIZARD_WEAK_SLOWER_0D, trigger, 1))
        entries.append(spawn(Vec2(768.0, axis), SpawnId.DEN_LIZARD_WEAK_SLOWER_0D, trigger, 1))
        trigger += 800

    trigger = 8000
    for axis in _surrounded_by_reptiles_axes():
        entries.append(spawn(Vec2(axis, 256.0), SpawnId.DEN_LIZARD_WEAK_SLOWER_0D, trigger, 1))
        entries.append(spawn(Vec2(axis, 768.0), SpawnId.DEN_LIZARD_WEAK_SLOWER_0D, trigger, 1))
        trigger += 800
    return entries


def quest_build_the_lizquidation(_ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    edges = edge_midpoints()
    trigger = 1500
    for wave in range(10):
        count = wave + 6
        entries.append(spawn(edges.right, SpawnId.LIZARD_RANDOM_2E, trigger, count))
        entries.append(spawn(edges.left, SpawnId.LIZARD_RANDOM_2E, trigger, count))
        if wave == 4:
            entries.append(spawn(Vec2(TERRAIN_SIZE + 128.0, edges.right.y), SpawnId.ALIEN_DEADLY_FAST_2B, 1500, 2))
        trigger += 8000
    return entries


def quest_build_spiders_inc(_ctx: QuestContext) -> list[SpawnEntry]:
    edges = edge_midpoints()
    center = NATIVE_CENTER
    entries = [
        spawn(edges.bottom, SpawnId.SPIDER_SP1_AI7_TIMER_38, 500, 1),
        spawn(Vec2(center.x + 64.0, edges.bottom.y), SpawnId.SPIDER_SP1_AI7_TIMER_38, 500, 1),
        spawn(edges.top, SpawnId.SPIDER_SMALL_BLUE_40, 500, 4),
    ]

    trigger = 17000
    step_count = 0
    while trigger < 107000:
        count = step_count // 2 + 3
        entries.append(spawn(edges.bottom, SpawnId.SPIDER_SP1_AI7_TIMER_38, trigger, count))
        entries.append(spawn(edges.top, SpawnId.SPIDER_SP1_AI7_TIMER_38, trigger, count))
        trigger += 6000
        step_count += 1
    return entries


def quest_build_lizard_raze(_ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    edges = edge_midpoints()
    trigger = 1500
    while trigger < 91500:
        entries.append(spawn(edges.right, SpawnId.LIZARD_RANDOM_2E, trigger, 6))
        entries.append(spawn(edges.left, SpawnId.LIZARD_RANDOM_2E, trigger, 6))
        trigger += 6000
    entries.extend(
        [
            spawn(Vec2(128.0, 256.0), SpawnId.DEN_LIZARD_WEAK_0C, 10000, 1),
            spawn(Vec2(128.0, 384.0), SpawnId.DEN_LIZARD_WEAK_0C, 10000, 1),
            spawn(Vec2(128.0, 512.0), SpawnId.DEN_LIZARD_WEAK_0C, 10000, 1),
        ],
    )
    return entries


def quest_build_deja_vu(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    trigger = 2000
    step = 2000
    while step > 560:
        angle = random_angle(ctx.rng.rand_tagged(RngCallerStatic.QUEST_BUILD_DEJA_VU_ANGLE))
        for pos in radial_points(NATIVE_CENTER, angle, 0x54, 0xFC, 0x2A):
            entries.append(spawn(pos, SpawnId.DEN_LIZARD_WEAK_SLOWER_0D, trigger, 1))
        trigger += step
        step -= 0x50
    return entries


def quest_build_zombie_masters(ctx: QuestContext) -> list[SpawnEntry]:
    return [
        spawn(Vec2(256.0, 256.0), SpawnId.ZOMBIE_BOSS_SPAWNER_00, 1000, ctx.player_count),
        spawn(Vec2(512.0, 256.0), SpawnId.ZOMBIE_BOSS_SPAWNER_00, 6000, 1),
        spawn(Vec2(768.0, 256.0), SpawnId.ZOMBIE_BOSS_SPAWNER_00, 14000, ctx.player_count),
        spawn(Vec2(768.0, 768.0), SpawnId.ZOMBIE_BOSS_SPAWNER_00, 18000, 1),
    ]


__all__ = [
    "QuestContext",
    "SpawnEntry",
    "quest_build_deja_vu",
    "quest_build_hidden_evil",
    "quest_build_lizard_kings",
    "quest_build_lizard_raze",
    "quest_build_spiders_inc",
    "quest_build_surrounded_by_reptiles",
    "quest_build_the_blighting",
    "quest_build_the_killing",
    "quest_build_the_lizquidation",
    "quest_build_zombie_masters",
]
