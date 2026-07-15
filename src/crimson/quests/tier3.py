from __future__ import annotations

from grim.geom import Vec2
from grim.rand import CrandLike

from ..creatures.spawn import SpawnId
from ..perks import PerkId
from ..rng_caller_static import RngCallerStatic
from ..weapons import WeaponId
from .helpers import (
    center_point,
    edge_midpoints,
    line_points,
    radial_points,
    ring_points,
    spawn,
    spawn_at,
)
from .registry import register_quest
from .types import QuestContext, SpawnEntry


@register_quest(
    level="3.1",
    title="The Blighting",
    time_limit_ms=300000,
    start_weapon_id=WeaponId.PISTOL,
    unlock_perk_id=PerkId.TOXIC_AVENGER,
)
def build_3_1_the_blighting(ctx: QuestContext, *, rng: CrandLike, full_version: bool = True) -> list[SpawnEntry]:
    edges = edge_midpoints(ctx.width)
    edges_wide = edge_midpoints(ctx.width, offset=128.0)
    entries = [
        spawn_at(
            edges_wide.right,
            heading=0.0,
            spawn_id=SpawnId.ALIEN_CONST_RED_FAST_2B,
            trigger_ms=1500,
            count=2,
        ),
        spawn_at(edges_wide.left, heading=0.0, spawn_id=SpawnId.ALIEN_CONST_RED_FAST_2B, trigger_ms=1500, count=2),
        spawn(
            Vec2(896.0, 128.0),
            heading=0.0,
            spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_1D_FAST_07,
            trigger_ms=2000,
            count=1,
        ),
        spawn(
            Vec2(128.0, 128.0),
            heading=0.0,
            spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_1D_FAST_07,
            trigger_ms=2000,
            count=1,
        ),
        spawn(
            Vec2(128.0, 896.0),
            heading=0.0,
            spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_1D_FAST_07,
            trigger_ms=2000,
            count=1,
        ),
        spawn(
            Vec2(896.0, 896.0),
            heading=0.0,
            spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_1D_FAST_07,
            trigger_ms=2000,
            count=1,
        ),
    ]

    trigger = 4000
    for wave in range(8):
        if wave in (2, 4):
            entries.append(
                spawn_at(
                    edges_wide.left,
                    heading=0.0,
                    spawn_id=SpawnId.ALIEN_CONST_RED_FAST_2B,
                    trigger_ms=trigger,
                    count=4,
                ),
            )
        if wave in (3, 5):
            entries.append(
                spawn_at(
                    Vec2(1152.0, edges_wide.right.y),
                    heading=0.0,
                    spawn_id=SpawnId.ALIEN_CONST_RED_FAST_2B,
                    trigger_ms=trigger,
                    count=4,
                ),
            )
        spawn_id = SpawnId.AI1_ALIEN_BLUE_TINT_1A if wave % 2 == 0 else SpawnId.AI1_LIZARD_BLUE_TINT_1C
        edge = wave % 5
        if edge == 0:
            entries.append(
                spawn_at(
                    edges.right,
                    heading=0.0,
                    spawn_id=spawn_id,
                    trigger_ms=trigger,
                    count=12,
                ),
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
                ),
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
                ),
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
                ),
            )
            trigger += 15000
        trigger += 1000
    return entries


@register_quest(
    level="3.2",
    title="Lizard Kings",
    time_limit_ms=180000,
    start_weapon_id=WeaponId.PISTOL,
    unlock_weapon_id=WeaponId.MULTI_PLASMA,
)
def build_3_2_lizard_kings(ctx: QuestContext, *, rng: CrandLike, full_version: bool = True) -> list[SpawnEntry]:
    center = center_point(ctx.width, ctx.height)
    entries = [
        spawn(
            Vec2(1152.0, 512.0),
            heading=0.0,
            spawn_id=SpawnId.FORMATION_CHAIN_LIZARD_4_11,
            trigger_ms=1500,
            count=1,
        ),
        spawn(
            Vec2(-128.0, 512.0),
            heading=0.0,
            spawn_id=SpawnId.FORMATION_CHAIN_LIZARD_4_11,
            trigger_ms=1500,
            count=1,
        ),
        spawn(
            Vec2(1152.0, 896.0),
            heading=0.0,
            spawn_id=SpawnId.FORMATION_CHAIN_LIZARD_4_11,
            trigger_ms=1500,
            count=1,
        ),
    ]
    trigger = 1500
    for pos, angle in ring_points(center, 256.0, 28, step=0.34906587):
        entries.append(
            spawn(
                pos,
                heading=-angle,
                spawn_id=SpawnId.LIZARD_RANDOM_31,
                trigger_ms=trigger,
                count=1,
            ),
        )
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
    return spawn(
        Vec2(x, y),
        heading=0.0,
        spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_1D_FAST_07,
        trigger_ms=trigger_ms,
        count=3,
    )


@register_quest(
    level="3.3",
    title="The Killing",
    time_limit_ms=300000,
    start_weapon_id=WeaponId.PISTOL,
    unlock_perk_id=PerkId.REGENERATION,
)
def build_3_3_the_killing(
    ctx: QuestContext,
    *,
    rng: CrandLike,
    full_version: bool = True,
) -> list[SpawnEntry]:
    edges = edge_midpoints(ctx.width)
    entries: list[SpawnEntry] = []
    trigger = 2000
    for wave in range(10):
        # Native bug (0x4384a0): both picks roll `crt_rand()` but discard the
        # result and branch on the wave counter, so the wave layout is a fixed
        # cycle while the rng stream still advances two draws per wave.
        rng.rand_tagged(RngCallerStatic.QUEST_BUILD_THE_KILLING_TEMPLATE_PICK)
        spawn_cycle = wave % 3
        if spawn_cycle == 0:
            spawn_id = SpawnId.AI1_ALIEN_BLUE_TINT_1A
        elif spawn_cycle == 1:
            spawn_id = SpawnId.AI1_SPIDER_SP1_BLUE_TINT_1B
        else:
            spawn_id = SpawnId.AI1_LIZARD_BLUE_TINT_1C

        rng.rand_tagged(RngCallerStatic.QUEST_BUILD_THE_KILLING_LAYOUT_PICK)
        edge = wave % 5
        if edge == 0:
            entries.append(
                spawn_at(
                    edges.right,
                    heading=0.0,
                    spawn_id=spawn_id,
                    trigger_ms=trigger,
                    count=12,
                ),
            )
        elif edge == 1:
            entries.append(
                spawn_at(
                    edges.left,
                    heading=0.0,
                    spawn_id=spawn_id,
                    trigger_ms=trigger,
                    count=12,
                ),
            )
        elif edge == 2:
            entries.append(
                spawn_at(
                    edges.bottom,
                    heading=0.0,
                    spawn_id=spawn_id,
                    trigger_ms=trigger,
                    count=12,
                ),
            )
        elif edge == 3:
            entries.append(
                spawn_at(
                    edges.top,
                    heading=0.0,
                    spawn_id=spawn_id,
                    trigger_ms=trigger,
                    count=12,
                ),
            )
        else:
            entries.append(
                _the_killing_random_spawner(
                    rng=rng,
                    trigger_ms=trigger,
                    y_caller=RngCallerStatic.QUEST_BUILD_THE_KILLING_SPAWNER_1_Y,
                    x_caller=RngCallerStatic.QUEST_BUILD_THE_KILLING_SPAWNER_1_X,
                ),
            )
            entries.append(
                _the_killing_random_spawner(
                    rng=rng,
                    trigger_ms=trigger + 1000,
                    y_caller=RngCallerStatic.QUEST_BUILD_THE_KILLING_SPAWNER_2_Y,
                    x_caller=RngCallerStatic.QUEST_BUILD_THE_KILLING_SPAWNER_2_X,
                ),
            )
            entries.append(
                _the_killing_random_spawner(
                    rng=rng,
                    trigger_ms=trigger + 2000,
                    y_caller=RngCallerStatic.QUEST_BUILD_THE_KILLING_SPAWNER_3_Y,
                    x_caller=RngCallerStatic.QUEST_BUILD_THE_KILLING_SPAWNER_3_X,
                ),
            )

        trigger += 6000
    return entries


@register_quest(
    level="3.4",
    title="Hidden Evil",
    time_limit_ms=300000,
    start_weapon_id=WeaponId.PISTOL,
    unlock_weapon_id=WeaponId.SEEKER_ROCKETS,
)
def build_3_4_hidden_evil(ctx: QuestContext, *, rng: CrandLike, full_version: bool = True) -> list[SpawnEntry]:
    edges = edge_midpoints(ctx.width, ctx.height)
    return [
        spawn_at(edges.bottom, heading=0.0, spawn_id=SpawnId.ALIEN_CONST_PURPLE_GHOST_21, trigger_ms=500, count=50),
        spawn_at(edges.bottom, heading=0.0, spawn_id=SpawnId.ALIEN_CONST_GREEN_GHOST_22, trigger_ms=15000, count=30),
        spawn_at(
            edges.bottom,
            heading=0.0,
            spawn_id=SpawnId.ALIEN_CONST_GREEN_GHOST_SMALL_23,
            trigger_ms=25000,
            count=20,
        ),
        spawn_at(
            edges.bottom,
            heading=0.0,
            spawn_id=SpawnId.ALIEN_CONST_GREEN_GHOST_SMALL_23,
            trigger_ms=30000,
            count=30,
        ),
        spawn_at(edges.bottom, heading=0.0, spawn_id=SpawnId.ALIEN_CONST_GREEN_GHOST_22, trigger_ms=35000, count=30),
    ]


@register_quest(
    level="3.5",
    title="Surrounded By Reptiles",
    time_limit_ms=300000,
    start_weapon_id=WeaponId.PISTOL,
    unlock_perk_id=PerkId.PYROMANIAC,
)
def build_3_5_surrounded_by_reptiles(
    ctx: QuestContext,
    *,
    rng: CrandLike,
    full_version: bool = True,
) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    trigger = 1000
    for pos in line_points(Vec2(256.0, 256.0), Vec2(0.0, 102.4), 5):
        entries.append(
            spawn(
                Vec2(256.0, pos.y),
                heading=0.0,
                spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_31_SLOW_0D,
                trigger_ms=trigger,
                count=1,
            ),
        )
        entries.append(
            spawn(
                Vec2(768.0, pos.y),
                heading=0.0,
                spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_31_SLOW_0D,
                trigger_ms=trigger,
                count=1,
            ),
        )
        trigger += 800

    trigger = 8000
    for pos in line_points(Vec2(256.0, 256.0), Vec2(102.4, 0.0), 5):
        entries.append(
            spawn(
                Vec2(pos.x, 256.0),
                heading=0.0,
                spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_31_SLOW_0D,
                trigger_ms=trigger,
                count=1,
            ),
        )
        entries.append(
            spawn(
                Vec2(pos.x, 768.0),
                heading=0.0,
                spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_31_SLOW_0D,
                trigger_ms=trigger,
                count=1,
            ),
        )
        trigger += 800
    return entries


@register_quest(
    level="3.6",
    title="The Lizquidation",
    time_limit_ms=300000,
    start_weapon_id=WeaponId.PISTOL,
    unlock_weapon_id=WeaponId.BLOW_TORCH,
)
def build_3_6_the_lizquidation(ctx: QuestContext, *, rng: CrandLike, full_version: bool = True) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    edges = edge_midpoints(ctx.width)
    trigger = 1500
    for wave in range(10):
        count = wave + 6
        entries.append(
            spawn_at(
                edges.right,
                heading=0.0,
                spawn_id=SpawnId.LIZARD_RANDOM_2E,
                trigger_ms=trigger,
                count=count,
            ),
        )
        entries.append(
            spawn_at(
                edges.left,
                heading=0.0,
                spawn_id=SpawnId.LIZARD_RANDOM_2E,
                trigger_ms=trigger,
                count=count,
            ),
        )
        if wave == 4:
            entries.append(
                spawn(
                    Vec2(ctx.width + 128.0, edges.right.y),
                    heading=0.0,
                    spawn_id=SpawnId.ALIEN_CONST_RED_FAST_2B,
                    trigger_ms=1500,
                    count=2,
                ),
            )
        trigger += 8000
    return entries


@register_quest(
    level="3.7",
    title="Spiders Inc.",
    time_limit_ms=300000,
    start_weapon_id=WeaponId.PLASMA_MINIGUN,
    unlock_perk_id=PerkId.NINJA,
)
def build_3_7_spiders_inc(ctx: QuestContext, *, rng: CrandLike, full_version: bool = True) -> list[SpawnEntry]:
    edges = edge_midpoints(ctx.width)
    center = center_point(ctx.width, ctx.height)
    entries = [
        spawn_at(edges.bottom, heading=0.0, spawn_id=SpawnId.SPIDER_SP1_AI7_TIMER_38, trigger_ms=500, count=1),
        spawn(
            Vec2(center.x + 64.0, edges.bottom.y),
            heading=0.0,
            spawn_id=SpawnId.SPIDER_SP1_AI7_TIMER_38,
            trigger_ms=500,
            count=1,
        ),
        spawn_at(edges.top, heading=0.0, spawn_id=SpawnId.SPIDER_SP1_CONST_BLUE_40, trigger_ms=500, count=4),
    ]

    trigger = 17000
    step_count = 0
    while trigger < 107000:
        count = step_count // 2 + 3
        entries.append(
            spawn_at(
                edges.bottom,
                heading=0.0,
                spawn_id=SpawnId.SPIDER_SP1_AI7_TIMER_38,
                trigger_ms=trigger,
                count=count,
            ),
        )
        entries.append(
            spawn_at(
                edges.top,
                heading=0.0,
                spawn_id=SpawnId.SPIDER_SP1_AI7_TIMER_38,
                trigger_ms=trigger,
                count=count,
            ),
        )
        trigger += 6000
        step_count += 1
    return entries


@register_quest(
    level="3.8",
    title="Lizard Raze",
    time_limit_ms=300000,
    start_weapon_id=WeaponId.PISTOL,
    unlock_weapon_id=WeaponId.ROCKET_MINIGUN,
)
def build_3_8_lizard_raze(ctx: QuestContext, *, rng: CrandLike, full_version: bool = True) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    edges = edge_midpoints(ctx.width)
    trigger = 1500
    while trigger < 91500:
        entries.append(
            spawn_at(
                edges.right,
                heading=0.0,
                spawn_id=SpawnId.LIZARD_RANDOM_2E,
                trigger_ms=trigger,
                count=6,
            ),
        )
        entries.append(
            spawn_at(
                edges.left,
                heading=0.0,
                spawn_id=SpawnId.LIZARD_RANDOM_2E,
                trigger_ms=trigger,
                count=6,
            ),
        )
        trigger += 6000
    entries.extend(
        [
            spawn(
                Vec2(128.0, 256.0),
                heading=0.0,
                spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_31_FAST_0C,
                trigger_ms=10000,
                count=1,
            ),
            spawn(
                Vec2(128.0, 384.0),
                heading=0.0,
                spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_31_FAST_0C,
                trigger_ms=10000,
                count=1,
            ),
            spawn(
                Vec2(128.0, 512.0),
                heading=0.0,
                spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_31_FAST_0C,
                trigger_ms=10000,
                count=1,
            ),
        ],
    )
    return entries


@register_quest(
    level="3.9",
    title="Deja vu",
    time_limit_ms=120000,
    start_weapon_id=WeaponId.GAUSS_GUN,
    unlock_perk_id=PerkId.HIGHLANDER,
)
def build_3_9_deja_vu(
    ctx: QuestContext,
    *,
    rng: CrandLike,
    full_version: bool = True,
) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    center = center_point(ctx.width, ctx.height)
    trigger = 2000
    step = 2000
    while step > 560:
        angle = (
            float(
                rng.rand_tagged(RngCallerStatic.QUEST_BUILD_DEJA_VU_ANGLE)
                % 612,
            )
            * 0.01
        )
        for pos in radial_points(center, angle, 0x54, 0xFC, 0x2A):
            entries.append(
                spawn(
                    pos,
                    heading=0.0,
                    spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_31_SLOW_0D,
                    trigger_ms=trigger,
                    count=1,
                ),
            )
        trigger += step
        step -= 0x50
    return entries


@register_quest(
    level="3.10",
    title="Zombie Masters",
    time_limit_ms=300000,
    start_weapon_id=WeaponId.PISTOL,
    unlock_weapon_id=WeaponId.JACKHAMMER,
)
def build_3_10_zombie_masters(ctx: QuestContext, *, rng: CrandLike, full_version: bool = True) -> list[SpawnEntry]:
    return [
        spawn(
            Vec2(256.0, 256.0),
            heading=0.0,
            spawn_id=SpawnId.ZOMBIE_BOSS_SPAWNER_00,
            trigger_ms=1000,
            count=ctx.player_count,
        ),
        spawn(Vec2(512.0, 256.0), heading=0.0, spawn_id=SpawnId.ZOMBIE_BOSS_SPAWNER_00, trigger_ms=6000, count=1),
        spawn(
            Vec2(768.0, 256.0),
            heading=0.0,
            spawn_id=SpawnId.ZOMBIE_BOSS_SPAWNER_00,
            trigger_ms=14000,
            count=ctx.player_count,
        ),
        spawn(
            Vec2(768.0, 768.0),
            heading=0.0,
            spawn_id=SpawnId.ZOMBIE_BOSS_SPAWNER_00,
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
