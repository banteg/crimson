from __future__ import annotations

from grim.geom import Vec2

from ..creatures.spawn import SpawnId
from ..math_parity import NATIVE_TAU, f32, x87_pc24_add, x87_pc24_div, x87_pc24_mul
from ..sim.state_types import TERRAIN_SIZE
from .helpers import (
    NATIVE_CENTER,
    angle_step,
    edge_midpoints,
    ring_point,
    ring_points,
    spawn,
)
from .types import QuestContext, SpawnEntry


def quest_build_major_alien_breach(_ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    edges = edge_midpoints()
    trigger = 4000
    for offset in range(0, 0x5DC, 0xF):
        entries.append(spawn(edges.right, SpawnId.ALIEN_RANDOM_GREEN_20, trigger, 2))
        entries.append(spawn(edges.top, SpawnId.ALIEN_RANDOM_GREEN_20, trigger, 2))
        trigger += 2000 - offset
        if trigger < 1000:
            trigger = 1000
    return entries


def quest_build_zombie_time(_ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    edges = edge_midpoints()
    trigger = 1500
    while trigger < 0x17CDC:
        entries.append(spawn(edges.right, SpawnId.ZOMBIE_RANDOM_41, trigger, 8))
        entries.append(spawn(edges.left, SpawnId.ZOMBIE_RANDOM_41, trigger, 8))
        trigger += 8000
    return entries


def quest_build_lizard_zombie_pact(_ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    edges = edge_midpoints()
    trigger = 1500
    wave = 0
    while trigger < 0x1BB5C:
        entries.append(spawn(edges.right, SpawnId.ZOMBIE_RANDOM_41, trigger, 6))
        entries.append(spawn(edges.left, SpawnId.ZOMBIE_RANDOM_41, trigger, 6))
        if wave % 5 == 0:
            idx = wave // 5
            entries.append(spawn(Vec2(356.0, float(idx * 0xB4 + 0x100)), SpawnId.DEN_LIZARD_WEAK_0C, trigger, idx + 1))
            entries.append(spawn(Vec2(356.0, float(idx * 0xB4 + 0x180)), SpawnId.DEN_LIZARD_WEAK_0C, trigger, idx + 2))
        trigger += 7000
        wave += 1
    return entries


def quest_build_the_collaboration(_ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    edges = edge_midpoints()
    trigger = 1500
    wave = 0
    while trigger < 0x2B55C:
        count = int(x87_pc24_add(x87_pc24_mul(float(wave), f32(0.8)), 7.0))
        entries.append(spawn(edges.right, SpawnId.AI1_ALIEN_BLUE_TINT_1A, trigger, count))
        entries.append(spawn(edges.bottom, SpawnId.AI1_SPIDER_SP1_BLUE_TINT_1B, trigger, count))
        entries.append(spawn(edges.left, SpawnId.AI1_LIZARD_BLUE_TINT_1C, trigger, count))
        entries.append(spawn(edges.top, SpawnId.ZOMBIE_RANDOM_41, trigger, count))
        trigger += 11000
        wave += 1
    return entries


def quest_build_the_massacre(_ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    edges = edge_midpoints()
    edges_wide = edge_midpoints(offset=128.0)
    trigger = 1500
    wave = 0
    while trigger < 0x1656C:
        entries.append(spawn(edges.right, SpawnId.ZOMBIE_RANDOM_41, trigger, wave + 3))
        if wave % 2 == 0:
            entries.append(spawn(edges_wide.right, SpawnId.ALIEN_DEADLY_FAST_2B, trigger, wave + 1))
        trigger += 5000
        wave += 1
    return entries


def quest_build_the_unblitzkrieg(_ctx: QuestContext) -> list[SpawnEntry]:
    def spawn_id_for(toggle: bool) -> SpawnId:
        return SpawnId.DEN_LIZARD_WEAK_SLOWER_0D if toggle else SpawnId.DEN_ALIEN_BASIC_07

    entries: list[SpawnEntry] = []
    trigger = 500

    i_var5 = 0
    for idx in range(10):
        y = float(i_var5 // 10 + 200)
        entries.append(spawn(Vec2(824.0, y), spawn_id_for(idx % 2 == 1), trigger, 1))
        trigger += 1800
        i_var5 += 0x270

    i_var5 = 0
    toggle = False
    for _ in range(10):
        x = float(0x338 - i_var5 // 10)
        entries.append(spawn(Vec2(x, 824.0), spawn_id_for(toggle), trigger, 1))
        trigger += 1500
        toggle = not toggle
        i_var5 += 0x270

    entries.append(spawn(Vec2(512.0, 512.0), SpawnId.DEN_ALIEN_BASIC_07, trigger, 1))

    i_var5 = 0
    toggle = False
    for _ in range(10):
        y = float(0x338 - i_var5 // 10)
        entries.append(spawn(Vec2(200.0, y), spawn_id_for(toggle), trigger, 1))
        trigger += 1200
        toggle = not toggle
        i_var5 += 0x270

    i_var5 = 0
    toggle = False
    for _ in range(10):
        x = float(i_var5 // 10 + 200)
        entries.append(spawn(Vec2(x, 200.0), spawn_id_for(toggle), trigger, 1))
        trigger += 800
        toggle = not toggle
        i_var5 += 0x270

    i_var5 = 0
    toggle = False
    for _ in range(10):
        y = float(i_var5 // 10 + 200)
        entries.append(spawn(Vec2(824.0, y), spawn_id_for(toggle), trigger, 1))
        trigger += 800
        toggle = not toggle
        i_var5 += 0x270

    i_var5 = 0
    toggle = False
    for _ in range(10):
        x = float(0x338 - i_var5 // 10)
        entries.append(spawn(Vec2(x, 824.0), spawn_id_for(toggle), trigger, 1))
        trigger += 700
        toggle = not toggle
        i_var5 += 0x270

    i_var5 = 0
    toggle = False
    for _ in range(10):
        y = float(0x338 - i_var5 // 10)
        entries.append(spawn(Vec2(200.0, y), spawn_id_for(toggle), trigger, 1))
        trigger += 700
        toggle = not toggle
        i_var5 += 0x270

    i_var5 = 0
    toggle = False
    for _ in range(10):
        x = float(i_var5 // 10 + 200)
        entries.append(spawn(Vec2(x, 200.0), spawn_id_for(toggle), trigger, 1))
        trigger += 800
        toggle = not toggle
        i_var5 += 0x270
    return entries


def _gauntlet_ring(radius: float, count: int) -> list[Vec2]:
    # `(float)index * 6.2831855f / (float)count`, each x87 op rounded (0x004369de).
    return [
        ring_point(NATIVE_CENTER, radius, x87_pc24_div(x87_pc24_mul(float(index), NATIVE_TAU), float(count)))
        for index in range(count)
    ]


def quest_build_gauntlet(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    player_count = ctx.player_count + (4 if ctx.hardcore else 0)
    edges = edge_midpoints()

    ring_count = player_count + 9
    if ring_count > 0:
        trigger = 0
        for pos in _gauntlet_ring(158.0, ring_count):
            entries.append(spawn(pos, SpawnId.DEN_SPIDER_BASIC_0A, trigger, 1))
            trigger += 200

    if ring_count > 0:
        trigger = 4000
        for count in range(2, ring_count + 2):
            entries.append(spawn(edges.right, SpawnId.ZOMBIE_RANDOM_41, trigger, count))
            entries.append(spawn(edges.left, SpawnId.ZOMBIE_RANDOM_41, trigger, count))
            entries.append(spawn(edges.bottom, SpawnId.ZOMBIE_RANDOM_41, trigger, count))
            entries.append(spawn(edges.top, SpawnId.ZOMBIE_RANDOM_41, trigger, count))
            trigger += 5500

    outer_count = player_count + 0x11
    if outer_count > 0:
        trigger = 42500
        for pos in _gauntlet_ring(258.0, outer_count):
            entries.append(spawn(pos, SpawnId.DEN_SPIDER_BASIC_0A, trigger, 1))
            trigger += 500
    return entries


def quest_build_syntax_terror(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    player_count = ctx.player_count + (4 if ctx.hardcore else 0)
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
                entries.append(spawn(Vec2(float(x), float(y)), SpawnId.DEN_ALIEN_BASIC_07, trigger, 1))
                trigger += 300
                inner_seed += 0x15
            trigger_base += 30000
        outer_seed += 0x35
        outer_index += 1
    return entries


def quest_build_the_annihilation(_ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    half_w = TERRAIN_SIZE // 2
    entries.append(spawn(Vec2(128.0, float(half_w)), SpawnId.ALIEN_DEADLY_FAST_2B, 500, 2))

    trigger = 500
    i_var5 = 0
    for idx in range(12):
        y = float(i_var5 // 12 + 0x80)
        x = 832.0 if idx % 2 == 0 else 896.0
        entries.append(spawn(Vec2(x, y), SpawnId.DEN_ALIEN_BASIC_07, trigger, 1))
        trigger += 500
        i_var5 += 0x300

    trigger = 45000
    i_var5 = 0
    toggle = False
    for _ in range(12):
        y = float(i_var5 // 12 + 0x80)
        x = 832.0 if toggle else 896.0
        entries.append(spawn(Vec2(x, y), SpawnId.DEN_ALIEN_BASIC_07, trigger, 1))
        trigger += 300
        toggle = not toggle
        i_var5 += 0x300
    return entries


def quest_build_the_end_of_all(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = [
        spawn(Vec2(128.0, 128.0), SpawnId.SPIDER_PLASMA_SHOOTER_3C, 3000, 1),
        spawn(Vec2(896.0, 128.0), SpawnId.SPIDER_PLASMA_SHOOTER_3C, 6000, 1),
        spawn(Vec2(128.0, 896.0), SpawnId.SPIDER_PLASMA_SHOOTER_3C, 9000, 1),
        spawn(Vec2(896.0, 896.0), SpawnId.SPIDER_PLASMA_SHOOTER_3C, 12000, 1),
    ]

    trigger = 13000
    for pos, _angle in ring_points(NATIVE_CENTER, 80.0, 6, step=1.0471976):
        entries.append(spawn(pos, SpawnId.DEN_ALIEN_BASIC_07, trigger, 1))
        trigger += 300

    entries.append(spawn(Vec2(512.0, 512.0), SpawnId.DEN_SPIDER_PLASMA_SHOOTERS_0B, trigger, 1))

    trigger = 18000
    y = 0x100
    toggle = False
    while y < 0x300:
        x = 1152.0 if toggle else -128.0
        entries.append(spawn(Vec2(x, float(y)), SpawnId.SPIDER_PLASMA_SHOOTER_3C, trigger, 2))
        trigger += 1000
        toggle = not toggle
        y += 0x80

    trigger = 43000
    for pos, _angle in ring_points(NATIVE_CENTER, 80.0, 6, step=1.0471976, start=0.5235988):
        entries.append(spawn(pos, SpawnId.DEN_ALIEN_BASIC_07, trigger, 1))
        trigger += 300

    if ctx.hardcore:
        trigger = 62800
        for ring_index in range(12):
            # `((float)ring_index + 1.0f) * 0.5235988f`
            pos = ring_point(NATIVE_CENTER, 180.0, angle_step(ring_index + 1, 0.5235988))
            entries.append(spawn(pos, SpawnId.DEN_ALIEN_BASIC_07, trigger, 1))
            trigger += 500

    trigger = 48000
    y = 0x100
    toggle = False
    while y < 0x300:
        x = 1152.0 if toggle else -128.0
        entries.append(spawn(Vec2(x, float(y)), SpawnId.SPIDER_PLASMA_SHOOTER_3C, trigger, 2))
        trigger += 1000
        toggle = not toggle
        y += 0x80

    return entries


__all__ = [
    "QuestContext",
    "SpawnEntry",
    "quest_build_gauntlet",
    "quest_build_lizard_zombie_pact",
    "quest_build_major_alien_breach",
    "quest_build_syntax_terror",
    "quest_build_the_annihilation",
    "quest_build_the_collaboration",
    "quest_build_the_end_of_all",
    "quest_build_the_massacre",
    "quest_build_the_unblitzkrieg",
    "quest_build_zombie_time",
]
