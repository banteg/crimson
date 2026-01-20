from __future__ import annotations

import math

from ..perks import PerkId
from .registry import register_quest
from .types import QuestContext, SpawnEntry

SPAWN_ID_7 = 0x07
SPAWN_ID_10 = 0x0A
SPAWN_ID_11 = 0x0B
SPAWN_ID_12 = 0x0C
SPAWN_ID_13 = 0x0D
SPAWN_ID_26 = 0x1A
SPAWN_ID_27 = 0x1B
SPAWN_ID_28 = 0x1C
SPAWN_ID_32 = 0x20
SPAWN_ID_43 = 0x2B
SPAWN_ID_60 = 0x3C
SPAWN_ID_65 = 0x41

@register_quest(
    level="4.1",
    title="Major Alien Breach",
    time_limit_ms=300000,
    start_weapon_id=18,
    unlock_perk_id=PerkId.JINXED,
    builder_address=0x00437af0,
)
def build_4_1_major_alien_breach(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    trigger = 4000
    half_w = ctx.width // 2
    for offset in range(0, 0x5DC, 0xF):
        entries.append(
            SpawnEntry(ctx.width + 64.0, float(half_w), 0.0, SPAWN_ID_32, trigger, 2)
        )
        entries.append(
            SpawnEntry(float(half_w), -64.0, 0.0, SPAWN_ID_32, trigger, 2)
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
    builder_address=0x00437d70,
)
def build_4_2_zombie_time(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    trigger = 1500
    half_w = ctx.width // 2
    while trigger < 0x17CDC:
        entries.append(
            SpawnEntry(ctx.width + 64.0, float(half_w), 0.0, SPAWN_ID_65, trigger, 8)
        )
        entries.append(SpawnEntry(-64.0, float(half_w), 0.0, SPAWN_ID_65, trigger, 8))
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
    trigger = 1500
    half_w = ctx.width // 2
    wave = 0
    while trigger < 0x1BB5C:
        entries.append(
            SpawnEntry(ctx.width + 64.0, float(half_w), 0.0, SPAWN_ID_65, trigger, 6)
        )
        entries.append(SpawnEntry(-64.0, float(half_w), 0.0, SPAWN_ID_65, trigger, 6))
        if wave % 5 == 0:
            idx = wave // 5
            entries.append(
                SpawnEntry(356.0, float(idx * 0xB4 + 0x100), 0.0, SPAWN_ID_12, trigger, idx + 1)
            )
            entries.append(
                SpawnEntry(356.0, float(idx * 0xB4 + 0x180), 0.0, SPAWN_ID_12, trigger, idx + 2)
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
    builder_address=0x00437f30,
)
def build_4_4_the_collaboration(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    trigger = 1500
    half_w = ctx.width // 2
    wave = 0
    while trigger < 0x2B55C:
        count = int(wave * 0.8 + 7)
        entries.append(
            SpawnEntry(ctx.width + 64.0, float(half_w), 0.0, SPAWN_ID_26, trigger, count)
        )
        entries.append(
            SpawnEntry(float(half_w), ctx.width + 64.0, 0.0, SPAWN_ID_27, trigger, count)
        )
        entries.append(SpawnEntry(-64.0, float(half_w), 0.0, SPAWN_ID_28, trigger, count))
        entries.append(SpawnEntry(float(half_w), -64.0, 0.0, SPAWN_ID_65, trigger, count))
        trigger += 11000
        wave += 1
    return entries

@register_quest(
    level="4.5",
    title="The Massacre",
    time_limit_ms=300000,
    start_weapon_id=1,
    unlock_perk_id=PerkId.REFLEX_BOOSTED,
    builder_address=0x004383e0,
)
def build_4_5_the_massacre(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    trigger = 1500
    half_w = ctx.width // 2
    wave = 0
    while trigger < 0x1656C:
        entries.append(
            SpawnEntry(ctx.width + 64.0, float(half_w), 0.0, SPAWN_ID_65, trigger, wave + 3)
        )
        if wave % 2 == 0:
            entries.append(
                SpawnEntry(ctx.width + 128.0, float(half_w), 0.0, SPAWN_ID_43, trigger, wave + 1)
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
    builder_address=0x00438a40,
)
def build_4_6_the_unblitzkrieg(ctx: QuestContext) -> list[SpawnEntry]:
    def spawn_id_for(toggle: bool) -> int:
        return SPAWN_ID_13 if toggle else SPAWN_ID_7

    entries: list[SpawnEntry] = []
    trigger = 500

    i_var5 = 0
    for idx in range(10):
        y = float(i_var5 // 10 + 200)
        entries.append(
            SpawnEntry(824.0, y, 0.0, spawn_id_for(idx % 2 == 1), trigger, 1)
        )
        trigger += 1800
        i_var5 += 0x270

    i_var5 = 0
    toggle = False
    for _ in range(10):
        x = float(0x338 - i_var5 // 10)
        entries.append(SpawnEntry(x, 824.0, 0.0, spawn_id_for(toggle), trigger, 1))
        trigger += 1500
        toggle = not toggle
        i_var5 += 0x270

    entries.append(SpawnEntry(512.0, 512.0, 0.0, SPAWN_ID_7, trigger, 1))

    i_var5 = 0
    toggle = False
    for _ in range(10):
        y = float(0x338 - i_var5 // 10)
        entries.append(SpawnEntry(200.0, y, 0.0, spawn_id_for(toggle), trigger, 1))
        trigger += 1200
        toggle = not toggle
        i_var5 += 0x270

    i_var5 = 0
    toggle = False
    for _ in range(10):
        x = float(i_var5 // 10 + 200)
        entries.append(SpawnEntry(x, 200.0, 0.0, spawn_id_for(toggle), trigger, 1))
        trigger += 800
        toggle = not toggle
        i_var5 += 0x270

    i_var5 = 0
    toggle = False
    for _ in range(10):
        y = float(i_var5 // 10 + 200)
        entries.append(SpawnEntry(824.0, y, 0.0, spawn_id_for(toggle), trigger, 1))
        trigger += 800
        toggle = not toggle
        i_var5 += 0x270

    i_var5 = 0
    toggle = False
    for _ in range(10):
        x = float(0x338 - i_var5 // 10)
        entries.append(SpawnEntry(x, 824.0, 0.0, spawn_id_for(toggle), trigger, 1))
        trigger += 700
        toggle = not toggle
        i_var5 += 0x270

    i_var5 = 0
    toggle = False
    for _ in range(10):
        y = float(0x338 - i_var5 // 10)
        entries.append(SpawnEntry(200.0, y, 0.0, spawn_id_for(toggle), trigger, 1))
        trigger += 700
        toggle = not toggle
        i_var5 += 0x270

    i_var5 = 0
    toggle = False
    for _ in range(10):
        x = float(i_var5 // 10 + 200)
        entries.append(SpawnEntry(x, 200.0, 0.0, spawn_id_for(toggle), trigger, 1))
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
    builder_address=0x004369a0,
)
def build_4_7_gauntlet(ctx: QuestContext, full_version: bool = True) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    player_count = ctx.player_count + (4 if full_version else 0)

    ring_count = player_count + 9
    if ring_count > 0:
        trigger = 0
        for idx in range(ring_count):
            angle = (idx * math.tau) / ring_count
            x = math.cos(angle) * 158.0 + 512.0
            y = math.sin(angle) * 158.0 + 512.0
            entries.append(SpawnEntry(x, y, 0.0, SPAWN_ID_10, trigger, 1))
            trigger += 200

    if ring_count > 0:
        trigger = 4000
        for count in range(2, ring_count + 2):
            half_w = ctx.width // 2
            entries.append(
                SpawnEntry(ctx.width + 64.0, float(half_w), 0.0, SPAWN_ID_65, trigger, count)
            )
            entries.append(
                SpawnEntry(-64.0, float(half_w), 0.0, SPAWN_ID_65, trigger, count)
            )
            entries.append(
                SpawnEntry(float(half_w), ctx.width + 64.0, 0.0, SPAWN_ID_65, trigger, count)
            )
            entries.append(
                SpawnEntry(float(half_w), -64.0, 0.0, SPAWN_ID_65, trigger, count)
            )
            trigger += 5500

    outer_count = player_count + 0x11
    if outer_count > 0:
        trigger = 42500
        for idx in range(outer_count):
            angle = (idx * math.tau) / outer_count
            x = math.cos(angle) * 258.0 + 512.0
            y = math.sin(angle) * 258.0 + 512.0
            entries.append(SpawnEntry(x, y, 0.0, SPAWN_ID_10, trigger, 1))
            trigger += 500
    return entries

@register_quest(
    level="4.8",
    title="Syntax Terror",
    time_limit_ms=300000,
    start_weapon_id=1,
    unlock_weapon_id=0x16,
    builder_address=0x00436c10,
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
                x = (
                    ((i * i * 0x4C + 0xEC) * i + outer_seed * outer_index) % 0x380
                ) + 0x40
                y = (
                    (inner_seed * i + (outer_index * outer_index * 0x4C + 0x1B) * outer_index)
                    % 0x380
                ) + 0x40
                entries.append(SpawnEntry(float(x), float(y), 0.0, SPAWN_ID_7, trigger, 1))
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
    builder_address=0x004382c0,
)
def build_4_9_the_annihilation(ctx: QuestContext) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = []
    half_w = ctx.width // 2
    entries.append(SpawnEntry(128.0, float(half_w), 0.0, SPAWN_ID_43, 500, 2))

    trigger = 500
    i_var5 = 0
    for idx in range(12):
        y = float(i_var5 // 12 + 0x80)
        x = 832.0 if idx % 2 == 0 else 896.0
        entries.append(SpawnEntry(x, y, 0.0, SPAWN_ID_7, trigger, 1))
        trigger += 500
        i_var5 += 0x300

    trigger = 45000
    i_var5 = 0
    toggle = False
    for _ in range(12):
        y = float(i_var5 // 12 + 0x80)
        x = 832.0 if toggle else 896.0
        entries.append(SpawnEntry(x, y, 0.0, SPAWN_ID_7, trigger, 1))
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
    builder_address=0x00438e10,
)
def build_4_10_the_end_of_all(ctx: QuestContext, full_version: bool = True) -> list[SpawnEntry]:
    entries: list[SpawnEntry] = [
        SpawnEntry(128.0, 128.0, 0.0, SPAWN_ID_60, 3000, 1),
        SpawnEntry(896.0, 128.0, 0.0, SPAWN_ID_60, 6000, 1),
        SpawnEntry(128.0, 896.0, 0.0, SPAWN_ID_60, 9000, 1),
        SpawnEntry(896.0, 896.0, 0.0, SPAWN_ID_60, 12000, 1),
    ]

    trigger = 13000
    for idx in range(6):
        angle = idx * 1.0471976
        x = math.cos(angle) * 80.0 + 512.0
        y = math.sin(angle) * 80.0 + 512.0
        entries.append(SpawnEntry(x, y, 0.0, SPAWN_ID_7, trigger, 1))
        trigger += 300

    entries.append(SpawnEntry(512.0, 512.0, 0.0, SPAWN_ID_11, trigger, 1))

    trigger = 18000
    y = 0x100
    toggle = False
    while y < 0x300:
        x = 1152.0 if toggle else -128.0
        entries.append(SpawnEntry(x, float(y), 0.0, SPAWN_ID_60, trigger, 2))
        trigger += 1000
        toggle = not toggle
        y += 0x80

    trigger = 43000
    for idx in range(6):
        angle = idx * 1.0471976 + 0.5235988
        x = math.cos(angle) * 80.0 + 512.0
        y = math.sin(angle) * 80.0 + 512.0
        entries.append(SpawnEntry(x, y, 0.0, SPAWN_ID_7, trigger, 1))
        trigger += 300

    if full_version:
        trigger = 62800
        for idx in range(12):
            angle = (idx + 1) * 0.5235988
            x = math.cos(angle) * 180.0 + 512.0
            y = math.sin(angle) * 180.0 + 512.0
            entries.append(SpawnEntry(x, y, 0.0, SPAWN_ID_7, trigger, 1))
            trigger += 500

    trigger = 48000
    y = 0x100
    toggle = False
    while y < 0x300:
        x = 1152.0 if toggle else -128.0
        entries.append(SpawnEntry(x, float(y), 0.0, SPAWN_ID_60, trigger, 2))
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
