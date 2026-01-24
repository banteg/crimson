from __future__ import annotations

"""Creature spawning helpers.

This module combines:
- a spawn-id labeling index (direct `type_id`/`flags` assignments extracted from
  `creature_spawn_template`, `FUN_00430af0`)
- a partial 1:1 rewrite of `creature_spawn_template` as a pure plan builder

Note: in the original game, `creature_spawn_template` is an algorithm (formations,
spawn slots, tail modifiers), so the spawn-id index here is only used for labeling
and debug UIs.

See also: `docs/creatures/spawn_plan.md` (porting model / invariants).
"""

from dataclasses import dataclass
from enum import IntEnum, IntFlag
import math

from ..crand import Crand


class CreatureTypeId(IntEnum):
    ZOMBIE = 0
    LIZARD = 1
    ALIEN = 2
    SPIDER_SP1 = 3
    SPIDER_SP2 = 4
    TROOPER = 5


class CreatureFlags(IntFlag):
    SELF_DAMAGE_TICK = 0x01  # periodic self-damage tick (dt * 60)
    SELF_DAMAGE_TICK_STRONG = 0x02  # stronger periodic self-damage tick (dt * 180)
    ANIM_PING_PONG = 0x04  # short ping-pong strip
    SPLIT_ON_DEATH = 0x08  # split-on-death behavior
    RANGED_ATTACK_SHOCK = 0x10  # ranged attack using projectile type 9
    ANIM_LONG_STRIP = 0x40  # force long animation strip
    AI7_LINK_TIMER = 0x80  # uses link index as timer for AI mode 7
    RANGED_ATTACK_VARIANT = 0x100  # ranged attack using orbit_radius as projectile type
    BONUS_ON_DEATH = 0x400  # spawns bonus on death


@dataclass(frozen=True, slots=True)
class SpawnTemplate:
    spawn_id: int
    type_id: CreatureTypeId | None
    flags: CreatureFlags | None
    creature: str | None
    anim_note: str | None
    tint_r: float | None = None
    tint_g: float | None = None
    tint_b: float | None = None
    tint_a: float | None = None
    size: float | None = None
    move_speed: float | None = None


TYPE_ID_TO_NAME = {
    0: "zombie",
    1: "lizard",
    2: "alien",
    3: "spider_sp1",
    4: "spider_sp2",
    5: "trooper",
}

# For many template ids, tint/size/move_speed are randomized or derived from other fields.
# We only fill them in when the game uses fixed constants (and keep the rest as `None`).
SPAWN_TEMPLATES = [
    SpawnTemplate(
        spawn_id=0x00,
        type_id=CreatureTypeId.ZOMBIE,
        flags=CreatureFlags.ANIM_PING_PONG | CreatureFlags.ANIM_LONG_STRIP,
        creature="zombie",
        anim_note="long strip (0x40 overrides 0x4)",
        tint_r=0.6,
        tint_g=0.6,
        tint_b=1.0,
        tint_a=0.8,
        size=64.0,
        move_speed=1.3,
    ),
    SpawnTemplate(
        spawn_id=0x01,
        type_id=CreatureTypeId.SPIDER_SP2,
        flags=CreatureFlags.SPLIT_ON_DEATH,
        creature="spider_sp2",
        anim_note=None,
        tint_r=0.8,
        tint_g=0.7,
        tint_b=0.4,
        tint_a=1.0,
        size=80.0,
        move_speed=2.0,
    ),
    SpawnTemplate(
        spawn_id=0x03,
        type_id=CreatureTypeId.SPIDER_SP1,
        flags=None,
        creature="spider_sp1",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x04,
        type_id=CreatureTypeId.LIZARD,
        flags=None,
        creature="lizard",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x05,
        type_id=CreatureTypeId.SPIDER_SP2,
        flags=None,
        creature="spider_sp2",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x06,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x07,
        type_id=CreatureTypeId.ALIEN,
        flags=CreatureFlags.ANIM_PING_PONG,
        creature="alien",
        anim_note="short strip (ping-pong)",
    ),
    SpawnTemplate(
        spawn_id=0x08,
        type_id=CreatureTypeId.ALIEN,
        flags=CreatureFlags.ANIM_PING_PONG,
        creature="alien",
        anim_note="short strip (ping-pong)",
    ),
    SpawnTemplate(
        spawn_id=0x09,
        type_id=CreatureTypeId.ALIEN,
        flags=CreatureFlags.ANIM_PING_PONG,
        creature="alien",
        anim_note="short strip (ping-pong)",
    ),
    SpawnTemplate(
        spawn_id=0x0A,
        type_id=CreatureTypeId.ALIEN,
        flags=CreatureFlags.ANIM_PING_PONG,
        creature="alien",
        anim_note="short strip (ping-pong)",
    ),
    SpawnTemplate(
        spawn_id=0x0B,
        type_id=CreatureTypeId.ALIEN,
        flags=CreatureFlags.ANIM_PING_PONG,
        creature="alien",
        anim_note="short strip (ping-pong)",
    ),
    SpawnTemplate(
        spawn_id=0x0C,
        type_id=CreatureTypeId.ALIEN,
        flags=CreatureFlags.ANIM_PING_PONG,
        creature="alien",
        anim_note="short strip (ping-pong)",
    ),
    SpawnTemplate(
        spawn_id=0x0D,
        type_id=CreatureTypeId.ALIEN,
        flags=CreatureFlags.ANIM_PING_PONG,
        creature="alien",
        anim_note="short strip (ping-pong)",
    ),
    SpawnTemplate(
        spawn_id=0x0E,
        type_id=CreatureTypeId.ALIEN,
        flags=CreatureFlags.ANIM_PING_PONG,
        creature="alien",
        anim_note="short strip (ping-pong)",
    ),
    SpawnTemplate(
        spawn_id=0x0F,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x10,
        type_id=CreatureTypeId.ALIEN,
        flags=CreatureFlags.ANIM_PING_PONG,
        creature="alien",
        anim_note="short strip (ping-pong)",
    ),
    SpawnTemplate(
        spawn_id=0x11,
        type_id=CreatureTypeId.LIZARD,
        flags=None,
        creature="lizard",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x12,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x13,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x14,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x15,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x16,
        type_id=CreatureTypeId.LIZARD,
        flags=None,
        creature="lizard",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x17,
        type_id=CreatureTypeId.SPIDER_SP1,
        flags=None,
        creature="spider_sp1",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x18,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x19,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x1A,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x1B,
        type_id=CreatureTypeId.SPIDER_SP1,
        flags=None,
        creature="spider_sp1",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x1C,
        type_id=CreatureTypeId.LIZARD,
        flags=None,
        creature="lizard",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x1D,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x1E,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x1F,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x20,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x21,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x22,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x23,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x24,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x25,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x26,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x27,
        type_id=CreatureTypeId.ALIEN,
        flags=CreatureFlags.BONUS_ON_DEATH,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x28,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x29,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x2A,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x2B,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x2C,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x2D,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x2E,
        type_id=CreatureTypeId.LIZARD,
        flags=None,
        creature="lizard",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x2F,
        type_id=CreatureTypeId.LIZARD,
        flags=None,
        creature="lizard",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x30,
        type_id=CreatureTypeId.LIZARD,
        flags=None,
        creature="lizard",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x31,
        type_id=CreatureTypeId.LIZARD,
        flags=None,
        creature="lizard",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x32,
        type_id=CreatureTypeId.SPIDER_SP1,
        flags=None,
        creature="spider_sp1",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x33,
        type_id=CreatureTypeId.SPIDER_SP1,
        flags=None,
        creature="spider_sp1",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x34,
        type_id=CreatureTypeId.SPIDER_SP1,
        flags=None,
        creature="spider_sp1",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x35,
        type_id=CreatureTypeId.SPIDER_SP2,
        flags=None,
        creature="spider_sp2",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x36,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x37,
        type_id=CreatureTypeId.SPIDER_SP2,
        flags=CreatureFlags.RANGED_ATTACK_VARIANT,
        creature="spider_sp2",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x38,
        type_id=CreatureTypeId.SPIDER_SP1,
        flags=CreatureFlags.AI7_LINK_TIMER,
        creature="spider_sp1",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x39,
        type_id=CreatureTypeId.SPIDER_SP1,
        flags=CreatureFlags.AI7_LINK_TIMER,
        creature="spider_sp1",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x3A,
        type_id=CreatureTypeId.SPIDER_SP1,
        flags=CreatureFlags.RANGED_ATTACK_SHOCK,
        creature="spider_sp1",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x3B,
        type_id=CreatureTypeId.SPIDER_SP1,
        flags=None,
        creature="spider_sp1",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x3C,
        type_id=CreatureTypeId.SPIDER_SP1,
        flags=CreatureFlags.RANGED_ATTACK_VARIANT,
        creature="spider_sp1",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x3D,
        type_id=CreatureTypeId.SPIDER_SP1,
        flags=None,
        creature="spider_sp1",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x3E,
        type_id=CreatureTypeId.SPIDER_SP1,
        flags=None,
        creature="spider_sp1",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x3F,
        type_id=CreatureTypeId.SPIDER_SP1,
        flags=None,
        creature="spider_sp1",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x40,
        type_id=CreatureTypeId.SPIDER_SP1,
        flags=None,
        creature="spider_sp1",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x41,
        type_id=CreatureTypeId.ZOMBIE,
        flags=None,
        creature="zombie",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x42,
        type_id=CreatureTypeId.ZOMBIE,
        flags=None,
        creature="zombie",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=0x43,
        type_id=CreatureTypeId.ZOMBIE,
        flags=None,
        creature="zombie",
        anim_note=None,
    ),
]

SPAWN_ID_TO_TEMPLATE = {entry.spawn_id: entry for entry in SPAWN_TEMPLATES}


def spawn_id_label(spawn_id: int) -> str:
    entry = SPAWN_ID_TO_TEMPLATE.get(spawn_id)
    if entry is None or entry.creature is None:
        return "unknown"
    return entry.creature


# Keep these in sync with `build_spawn_plan` and `tests/test_spawn_plan.py`.
SPAWN_IDS_PORTED = frozenset({0x00, 0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43})
SPAWN_IDS_VERIFIED = frozenset({0x00, 0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43})


@dataclass(frozen=True, slots=True, kw_only=True)
class SpawnEnv:
    terrain_width: float
    terrain_height: float
    demo_mode_active: bool
    hardcore: bool
    difficulty_level: int


@dataclass(frozen=True, slots=True, kw_only=True)
class BurstEffect:
    x: float
    y: float
    count: int


@dataclass(slots=True)
class CreatureInit:
    # Template id that produced this creature (not necessarily unique per creature in formations).
    origin_template_id: int

    pos_x: float
    pos_y: float

    # Headings are in radians. The original seeds a random heading early, then overwrites it
    # at the end with the function argument (or a randomized argument for `-100.0`).
    heading: float

    phase_seed: float

    type_id: CreatureTypeId | None = None
    flags: CreatureFlags = CreatureFlags(0)
    ai_mode: int = 0

    health: float | None = None
    max_health: float | None = None
    move_speed: float | None = None
    reward_value: float | None = None
    size: float | None = None
    contact_damage: float | None = None

    tint_r: float | None = None
    tint_g: float | None = None
    tint_b: float | None = None
    tint_a: float | None = None

    orbit_angle: float | None = None
    orbit_radius: float | None = None
    ranged_projectile_type: int | None = None

    # AI link semantics:
    # - For most formations (ai_mode 3/5/...), `ai_link_parent` references another creature index
    #   (typically the parent or previous element in the chain).
    # - For AI7 timer mode (flag 0x80), `ai_timer` is written into link_index.
    ai_link_parent: int | None = None
    ai_timer: int | None = None

    target_offset_x: float | None = None
    target_offset_y: float | None = None

    # Spawn slot reference (stored in link_index in the original when flags include 0x4).
    spawn_slot: int | None = None


@dataclass(slots=True)
class SpawnSlotInit:
    owner_creature: int
    timer: float
    count: int
    limit: int
    interval: float
    child_template_id: int


@dataclass(frozen=True, slots=True)
class SpawnPlan:
    creatures: tuple[CreatureInit, ...]
    spawn_slots: tuple[SpawnSlotInit, ...]
    effects: tuple[BurstEffect, ...]
    primary: int


def tick_spawn_slot(slot: SpawnSlotInit, frame_dt: float) -> int | None:
    """Advance a spawn slot timer by `frame_dt`, returning a spawned template id if triggered.

    Modeled after `creature_update_all`'s spawn-slot tick:
      timer -= dt
      if timer < 0:
        timer += interval
        if count < limit:
          count += 1
          spawn child_template_id

    Note: the original only adds `interval` once (no loop), so large dt can keep the timer negative.
    """
    slot.timer -= frame_dt
    if slot.timer < 0.0:
        slot.timer += slot.interval
        if slot.count < slot.limit:
            slot.count += 1
            return slot.child_template_id
    return None


def _alloc_creature(template_id: int, pos_x: float, pos_y: float, rng: Crand) -> CreatureInit:
    # creature_alloc_slot():
    # - clears flags
    # - seeds phase_seed = float(crt_rand() & 0x17f)
    phase_seed = float(rng.rand() & 0x17F)
    return CreatureInit(origin_template_id=template_id, pos_x=pos_x, pos_y=pos_y, heading=0.0, phase_seed=phase_seed)


def _clamp01(value: float) -> float:
    if value < 0.0:
        return 0.0
    if 1.0 < value:
        return 1.0
    return value


def build_survival_spawn_creature(pos: tuple[float, float], rng: Crand, *, player_experience: int) -> CreatureInit:
    """Pure model of `survival_spawn_creature` (crimsonland.exe 0x00407510).

    Note: this is not a `creature_spawn_template` spawn id; it picks a `type_id` and stats
    dynamically based on `player_experience`.
    """
    pos_x, pos_y = pos
    xp = int(player_experience)

    c = _alloc_creature(-1, pos_x, pos_y, rng)
    c.ai_mode = 0

    r10 = rng.rand() % 10

    if xp < 12000:
        type_id = 2 if r10 < 9 else 3
    elif xp < 25000:
        type_id = 0 if r10 < 4 else 3
        if 8 < r10:
            type_id = 2
    elif xp < 42000:
        if r10 < 5:
            type_id = 2
        else:
            # Decompiled as a sign-bit trick, but in practice this is a parity pick.
            type_id = (rng.rand() & 1) + 3
    elif xp < 50000:
        type_id = 2
    elif xp < 90000:
        type_id = 4
    else:
        if 109999 < xp:
            if r10 < 6:
                type_id = 2
            elif r10 < 9:
                type_id = 4
            else:
                type_id = 0
        else:
            type_id = 0

    # Rare override: forces spider_sp1 when (rand() & 0x1f) == 2.
    if (rng.rand() & 0x1F) == 2:
        type_id = 3

    c.type_id = CreatureTypeId(type_id)

    # size = rand() % 0x14 + 0x2c
    c.size = float(rng.rand() % 0x14 + 0x2C)

    # heading = (rand() % 0x13a) * 0.01
    c.heading = float(rng.rand() % 0x13A) * 0.01

    move_speed = float(xp // 4000) * 0.045 + 0.9
    if c.type_id == CreatureTypeId.SPIDER_SP1:
        c.flags |= CreatureFlags.AI7_LINK_TIMER
        move_speed *= 1.3

    r_health = rng.rand()
    health = float(xp) * 0.00125 + float(r_health & 0xF) + 52.0

    if c.type_id == CreatureTypeId.ZOMBIE:
        move_speed *= 0.6
        if move_speed < 1.3:
            move_speed = 1.3
        health *= 1.5

    if 3.5 < move_speed:
        move_speed = 3.5

    c.move_speed = move_speed
    c.health = health
    c.reward_value = 0.0
    c.tint_a = 1.0

    # Tint based on player_experience thresholds.
    if xp < 50_000:
        c.tint_r = 1.0 - 1.0 / (float(xp // 1000) + 10.0)
        c.tint_g = float(rng.rand() % 10) * 0.01 + 0.9 - 1.0 / (float(xp // 10000) + 10.0)
        c.tint_b = float(rng.rand() % 10) * 0.01 + 0.7
    elif xp < 100_000:
        c.tint_r = 0.9 - 1.0 / (float(xp // 1000) + 10.0)
        c.tint_g = float(rng.rand() % 10) * 0.01 + 0.8 - 1.0 / (float(xp // 10000) + 10.0)
        c.tint_b = float(xp - 50_000) * 6e-06 + float(rng.rand() % 10) * 0.01 + 0.7
    else:
        c.tint_r = 1.0 - 1.0 / (float(xp // 1000) + 10.0)
        c.tint_g = float(rng.rand() % 10) * 0.01 + 0.9 - 1.0 / (float(xp // 10000) + 10.0)
        tint_b = float(rng.rand() % 10) * 0.01 + 1.0 - float(xp - 100_000) * 3e-06
        if tint_b < 0.5:
            tint_b = 0.5
        c.tint_b = tint_b

    # contact_damage = size * 0.0952381
    c.contact_damage = float(c.size or 0.0) * (2.0 / 21.0)

    # reward_value is always 0.0 at this point in the original.
    c.reward_value = float(c.health or 0.0) * 0.4 + float(c.contact_damage or 0.0) * 0.8 + move_speed * 5.0 + float(rng.rand() % 10 + 10)

    # Rare stat overrides (color-coded variants).
    r = rng.rand()
    if r % 0xB4 < 2:
        c.tint_r = 0.9
        c.tint_g = 0.4
        c.tint_b = 0.4
        c.tint_a = 1.0
        c.health = 65.0
        c.reward_value = 320.0
    else:
        r = rng.rand()
        if r % 0xF0 < 2:
            c.tint_r = 0.4
            c.tint_g = 0.9
            c.tint_b = 0.4
            c.tint_a = 1.0
            c.health = 85.0
            c.reward_value = 420.0
        else:
            r = rng.rand()
            if r % 0x168 < 2:
                c.tint_r = 0.4
                c.tint_g = 0.4
                c.tint_b = 0.9
                c.tint_a = 1.0
                c.health = 125.0
                c.reward_value = 520.0

    # Rare health/size boosts (do not recompute contact_damage).
    r = rng.rand()
    if r % 0x528 < 4:
        c.tint_r = 0.84
        c.tint_g = 0.24
        c.tint_b = 0.89
        c.tint_a = 1.0
        c.size = 80.0
        c.reward_value = 600.0
        c.health = float(c.health or 0.0) + 230.0
    else:
        r = rng.rand()
        if r % 0x654 < 4:
            c.tint_r = 0.94
            c.tint_g = 0.84
            c.tint_b = 0.29
            c.tint_a = 1.0
            c.size = 85.0
            c.reward_value = 900.0
            c.health = float(c.health or 0.0) + 2230.0

    if c.health is not None:
        c.max_health = c.health
    if c.reward_value is not None:
        c.reward_value *= 0.8

    if c.tint_r is not None:
        c.tint_r = _clamp01(c.tint_r)
    if c.tint_g is not None:
        c.tint_g = _clamp01(c.tint_g)
    if c.tint_b is not None:
        c.tint_b = _clamp01(c.tint_b)
    if c.tint_a is not None:
        c.tint_a = _clamp01(c.tint_a)

    return c


def _rand_survival_spawn_pos(rng: Crand, *, terrain_width: int, terrain_height: int) -> tuple[float, float]:
    match rng.rand() & 3:
        case 0:
            return float(rng.rand() % terrain_width), -40.0
        case 1:
            return float(rng.rand() % terrain_width), float(terrain_height) + 40.0
        case 2:
            return -40.0, float(rng.rand() % terrain_height)
        case _:
            return float(terrain_width) + 40.0, float(rng.rand() % terrain_height)


def tick_survival_wave_spawns(
    spawn_cooldown: float,
    frame_dt_ms: float,
    rng: Crand,
    *,
    player_count: int,
    survival_elapsed_ms: float,
    player_experience: int,
    terrain_width: int,
    terrain_height: int,
) -> tuple[float, tuple[CreatureInit, ...]]:
    """Advance survival enemy wave spawning, returning updated cooldown + spawned creatures.

    Modeled after `survival_update` (crimsonland.exe 0x00407cd0) wave spawns:
      spawn_cooldown -= player_count * frame_dt_ms
      if spawn_cooldown <= -1:
        interval_ms = 500 - int(survival_elapsed_ms) / 0x708
        if interval_ms < 0:
          extra = (1 - interval_ms) >> 1
          interval_ms += extra * 2
          spawn `extra` creatures at random edges
        interval_ms = max(1, interval_ms)
        spawn_cooldown += interval_ms
        spawn 1 creature at a random edge
    """
    spawn_cooldown -= float(player_count) * frame_dt_ms
    if spawn_cooldown > -1.0:
        return spawn_cooldown, ()

    interval_ms = 500 - int(survival_elapsed_ms) // 0x708

    spawns: list[CreatureInit] = []
    if interval_ms < 0:
        extra = (1 - interval_ms) >> 1
        interval_ms += int(extra) * 2
        for _ in range(int(extra)):
            pos = _rand_survival_spawn_pos(rng, terrain_width=terrain_width, terrain_height=terrain_height)
            spawns.append(build_survival_spawn_creature(pos, rng, player_experience=player_experience))

    if interval_ms < 1:
        interval_ms = 1
    spawn_cooldown += float(interval_ms)

    pos = _rand_survival_spawn_pos(rng, terrain_width=terrain_width, terrain_height=terrain_height)
    spawns.append(build_survival_spawn_creature(pos, rng, player_experience=player_experience))

    return spawn_cooldown, tuple(spawns)


@dataclass(frozen=True, slots=True)
class SpawnTemplateCall:
    template_id: int
    pos: tuple[float, float]
    heading: float


def advance_survival_spawn_stage(stage: int, *, player_level: int) -> tuple[int, tuple[SpawnTemplateCall, ...]]:
    """Return scripted survival spawns for the current stage (aka `survival_update` milestones).

    Modeled after `survival_update` (crimsonland.exe 0x00407cd0) stage 0..10 gate checks.
    """
    stage = int(stage)
    level = int(player_level)

    spawns: list[SpawnTemplateCall] = []
    heading = float(math.pi)

    while True:
        if stage == 0:
            if level < 5:
                break
            stage = 1
            spawns.append(SpawnTemplateCall(template_id=0x12, pos=(-164.0, 512.0), heading=heading))
            spawns.append(SpawnTemplateCall(template_id=0x12, pos=(1188.0, 512.0), heading=heading))
            continue

        if stage == 1:
            if level < 9:
                break
            stage = 2
            spawns.append(SpawnTemplateCall(template_id=0x2C, pos=(1088.0, 512.0), heading=heading))
            continue

        if stage == 2:
            if level < 0xB:
                break
            stage = 3
            step = 128.0 / 3.0
            for i in range(0xC):
                spawns.append(SpawnTemplateCall(template_id=0x35, pos=(1088.0, float(i) * step + 256.0), heading=heading))
            continue

        if stage == 3:
            if level < 0xD:
                break
            stage = 4
            for i in range(4):
                spawns.append(SpawnTemplateCall(template_id=0x2B, pos=(1088.0, float(i) * 64.0 + 384.0), heading=heading))
            continue

        if stage == 4:
            if level < 0xF:
                break
            stage = 5
            for i in range(4):
                spawns.append(SpawnTemplateCall(template_id=0x38, pos=(1088.0, float(i) * 64.0 + 384.0), heading=heading))
            for i in range(4):
                spawns.append(SpawnTemplateCall(template_id=0x38, pos=(-64.0, float(i) * 64.0 + 384.0), heading=heading))
            continue

        if stage == 5:
            if level < 0x11:
                break
            stage = 6
            spawns.append(SpawnTemplateCall(template_id=0x3A, pos=(1088.0, 512.0), heading=heading))
            continue

        if stage == 6:
            if level < 0x13:
                break
            stage = 7
            spawns.append(SpawnTemplateCall(template_id=1, pos=(640.0, 512.0), heading=heading))
            continue

        if stage == 7:
            if level < 0x15:
                break
            stage = 8
            spawns.append(SpawnTemplateCall(template_id=1, pos=(384.0, 256.0), heading=heading))
            spawns.append(SpawnTemplateCall(template_id=1, pos=(640.0, 768.0), heading=heading))
            continue

        if stage == 8:
            if level < 0x1A:
                break
            stage = 9
            for i in range(4):
                spawns.append(SpawnTemplateCall(template_id=0x3C, pos=(1088.0, float(i) * 64.0 + 384.0), heading=heading))
            for i in range(4):
                spawns.append(SpawnTemplateCall(template_id=0x3C, pos=(-64.0, float(i) * 64.0 + 384.0), heading=heading))
            continue

        if stage == 9:
            if level <= 0x1F:
                break
            stage = 10
            spawns.append(SpawnTemplateCall(template_id=0x3A, pos=(1088.0, 512.0), heading=heading))
            spawns.append(SpawnTemplateCall(template_id=0x3A, pos=(-64.0, 512.0), heading=heading))
            for i in range(4):
                spawns.append(SpawnTemplateCall(template_id=0x3C, pos=(float(i) * 64.0 + 384.0, -64.0), heading=heading))
            for i in range(4):
                spawns.append(
                    SpawnTemplateCall(template_id=0x3C, pos=(float(i) * 64.0 + 384.0, 1088.0), heading=heading)
                )
            continue

        break

    return stage, tuple(spawns)


def build_rush_mode_spawn_creature(
    pos: tuple[float, float],
    tint_rgba: tuple[float, float, float, float],
    rng: Crand,
    *,
    type_id: int,
    survival_elapsed_ms: int,
) -> CreatureInit:
    """Pure model of `creature_spawn` (0x00428240) as used by `rush_mode_update` (0x004072b0)."""
    pos_x, pos_y = pos
    elapsed_ms = int(survival_elapsed_ms)

    c = _alloc_creature(-1, pos_x, pos_y, rng)
    c.type_id = CreatureTypeId(type_id)
    c.ai_mode = 0

    c.health = float(elapsed_ms) * 0.000100000005 + 10.0
    c.heading = float(rng.rand() % 0x13A) * 0.01
    c.move_speed = float(elapsed_ms) * 1.0000001e-05 + 2.5
    c.reward_value = float(rng.rand() % 0x1E + 0x8C)

    c.tint_r, c.tint_g, c.tint_b, c.tint_a = tint_rgba
    c.contact_damage = 4.0

    if c.health is not None:
        c.max_health = c.health
    c.size = float(elapsed_ms) * 1.0000001e-05 + 47.0

    return c


def tick_rush_mode_spawns(
    spawn_cooldown: float,
    frame_dt_ms: float,
    rng: Crand,
    *,
    player_count: int,
    survival_elapsed_ms: int,
    terrain_width: float,
    terrain_height: float,
) -> tuple[float, tuple[CreatureInit, ...]]:
    """Advance rush-mode edge wave spawning (pure model of `rush_mode_update` / 0x004072b0)."""
    spawn_cooldown -= float(player_count) * frame_dt_ms

    spawns: list[CreatureInit] = []
    while spawn_cooldown < 0.0:
        spawn_cooldown += 250.0

        t = float(int(float(survival_elapsed_ms) + 1.0))
        tint_r = _clamp01(t * 8.333333e-06 + 0.3)
        tint_g = _clamp01(t * 10000.0 + 0.3)
        tint_b = _clamp01(math.sin(t * 0.000100000005) + 0.3)
        tint_a = 1.0
        tint = (tint_r, tint_g, tint_b, tint_a)

        elapsed_ms = int(survival_elapsed_ms)
        theta = float(elapsed_ms) * 0.001
        spawn_right = (terrain_width + 64.0, terrain_height * 0.5 + math.cos(theta) * 256.0)
        spawn_left = (-64.0, terrain_height * 0.5 + math.sin(theta) * 256.0)

        c = build_rush_mode_spawn_creature(spawn_right, tint, rng, type_id=2, survival_elapsed_ms=elapsed_ms)
        c.ai_mode = 8
        spawns.append(c)

        c = build_rush_mode_spawn_creature(spawn_left, tint, rng, type_id=3, survival_elapsed_ms=elapsed_ms)
        c.ai_mode = 8
        c.flags |= CreatureFlags.AI7_LINK_TIMER
        if c.move_speed is not None:
            c.move_speed *= 1.4
        spawns.append(c)

    return spawn_cooldown, tuple(spawns)


def build_tutorial_stage3_fire_spawns() -> tuple[SpawnTemplateCall, ...]:
    """Spawn pack triggered by the stage-3 fire-key transition in `tutorial_timeline_update` (0x00408990)."""
    heading = float(math.pi)
    return (
        SpawnTemplateCall(template_id=0x24, pos=(-164.0, 412.0), heading=heading),
        SpawnTemplateCall(template_id=0x26, pos=(-184.0, 512.0), heading=heading),
        SpawnTemplateCall(template_id=0x24, pos=(-154.0, 612.0), heading=heading),
    )


def build_tutorial_stage4_clear_spawns() -> tuple[SpawnTemplateCall, ...]:
    """Spawn pack triggered by the stage-4 "all clear" transition in `tutorial_timeline_update` (0x00408990)."""
    heading = float(math.pi)
    return (
        SpawnTemplateCall(template_id=0x24, pos=(1188.0, 412.0), heading=heading),
        SpawnTemplateCall(template_id=0x26, pos=(1208.0, 512.0), heading=heading),
        SpawnTemplateCall(template_id=0x24, pos=(1178.0, 612.0), heading=heading),
    )


def build_tutorial_stage5_repeat_spawns(repeat_spawn_count: int) -> tuple[SpawnTemplateCall, ...]:
    """Spawn packs triggered by the stage-5 repeat loop in `tutorial_timeline_update` (0x00408990).

    `repeat_spawn_count` is the incremented counter value (1..7). When it reaches 8, the tutorial
    transitions instead of spawning more creatures.
    """
    n = int(repeat_spawn_count)
    if n < 1 or 8 <= n:
        return ()

    heading = float(math.pi)
    spawns: list[SpawnTemplateCall] = []

    if (n & 1) == 0:
        # Even: right-side spawn pack (with an off-screen bottom-right spawn).
        if n < 6:
            spawns.append(SpawnTemplateCall(template_id=0x27, pos=(1056.0, 1056.0), heading=heading))
        spawns.append(SpawnTemplateCall(template_id=0x24, pos=(1188.0, 1136.0), heading=heading))
        spawns.append(SpawnTemplateCall(template_id=0x26, pos=(1208.0, 512.0), heading=heading))
        spawns.append(SpawnTemplateCall(template_id=0x24, pos=(1178.0, 612.0), heading=heading))
        if n == 4:
            spawns.append(SpawnTemplateCall(template_id=0x40, pos=(512.0, 1056.0), heading=heading))
        return tuple(spawns)

    # Odd: left-side spawn pack.
    if n < 6:
        spawns.append(SpawnTemplateCall(template_id=0x27, pos=(-32.0, 1056.0), heading=heading))
    spawns.extend(build_tutorial_stage3_fire_spawns())
    return tuple(spawns)


def build_tutorial_stage6_perks_done_spawns() -> tuple[SpawnTemplateCall, ...]:
    """Spawn pack triggered by the stage-6 "no perks pending" transition in `tutorial_timeline_update` (0x00408990)."""
    heading = float(math.pi)
    return (
        *build_tutorial_stage3_fire_spawns(),
        SpawnTemplateCall(template_id=0x28, pos=(-32.0, -32.0), heading=heading),
        *build_tutorial_stage4_clear_spawns(),
    )


def _apply_tail(
    template_id: int,
    plan_creatures: list[CreatureInit],
    plan_spawn_slots: list[SpawnSlotInit],
    plan_effects: list[BurstEffect],
    primary_idx: int,
    final_heading: float,
    env: SpawnEnv,
) -> None:
    c = plan_creatures[primary_idx]

    # Demo-burst effect (skipped when demo_mode_active != 0).
    if (
        not env.demo_mode_active
        and 0.0 < c.pos_x < env.terrain_width
        and 0.0 < c.pos_y < env.terrain_height
    ):
        plan_effects.append(BurstEffect(x=c.pos_x, y=c.pos_y, count=8))

    if c.health is not None:
        c.max_health = c.health

    # Spider_sp1 "AI7 timer" auto-enable (applies to the *return* creature).
    if (
        c.type_id == CreatureTypeId.SPIDER_SP1
        and (int(c.flags) & 0x10) == 0
        and (int(c.flags) & 0x80) == 0
    ):
        c.flags |= CreatureFlags.AI7_LINK_TIMER
        c.ai_link_parent = None
        c.spawn_slot = None
        c.ai_timer = 0
        if c.move_speed is not None:
            c.move_speed *= 1.2

    # Hardcore tweak for template 0x38 only.
    if template_id == 0x38 and env.hardcore and c.move_speed is not None:
        c.move_speed *= 0.7

    c.heading = final_heading

    # Difficulty modifiers.
    has_spawn_slot = c.spawn_slot is not None and 0 <= c.spawn_slot < len(plan_spawn_slots)

    if not env.hardcore:
        # This is written as a short-circuit expression in the original:
        # for flag 0x4 creatures, always bump their spawn-slot interval by +0.2 in non-hardcore.
        if (int(c.flags) & int(CreatureFlags.ANIM_PING_PONG)) != 0 and has_spawn_slot:
            plan_spawn_slots[c.spawn_slot].interval += 0.2

        if env.difficulty_level > 0:
            d = env.difficulty_level
            if c.reward_value is not None and c.move_speed is not None and c.contact_damage is not None and c.health is not None:
                if d == 1:
                    c.reward_value *= 0.9
                    c.move_speed *= 0.95
                    c.contact_damage *= 0.95
                    c.health *= 0.95
                elif d == 2:
                    c.reward_value *= 0.85
                    c.move_speed *= 0.9
                    c.contact_damage *= 0.9
                    c.health *= 0.9
                elif d == 3:
                    c.reward_value *= 0.85
                    c.move_speed *= 0.8
                    c.contact_damage *= 0.8
                    c.health *= 0.8
                elif d == 4:
                    c.reward_value *= 0.8
                    c.move_speed *= 0.7
                    c.contact_damage *= 0.7
                    c.health *= 0.7
                else:
                    c.reward_value *= 0.8
                    c.move_speed *= 0.6
                    c.contact_damage *= 0.5
                    c.health *= 0.5

            if has_spawn_slot and (int(c.flags) & int(CreatureFlags.ANIM_PING_PONG)) != 0:
                plan_spawn_slots[c.spawn_slot].interval += min(3.0, float(d) * 0.35)
    else:
        # In hardcore: difficulty level is forcibly cleared (global), and creature stats are buffed.
        if c.move_speed is not None:
            c.move_speed *= 1.05
        if c.contact_damage is not None:
            c.contact_damage *= 1.4
        if c.health is not None:
            c.health *= 1.2

        if has_spawn_slot and (int(c.flags) & int(CreatureFlags.ANIM_PING_PONG)) != 0:
            plan_spawn_slots[c.spawn_slot].interval = max(
                0.1,
                plan_spawn_slots[c.spawn_slot].interval - 0.2,
            )
def _apply_unhandled_creature_type_fallback(plan_creatures: list[CreatureInit], primary_idx: int) -> None:
    # Some template paths jump to the "Unhandled creatureType.\n" debug block in the original,
    # which forcibly overwrites `type_id` and `health` on the *current* creature pointer.
    # See artifacts/creature_spawn_template/binja-hlil.txt (label_431099).
    c = plan_creatures[primary_idx]
    c.type_id = CreatureTypeId.ALIEN
    c.health = 20.0


def build_spawn_plan(template_id: int, pos: tuple[float, float], heading: float, rng: Crand, env: SpawnEnv) -> SpawnPlan:
    """Pure plan builder modeled after `creature_spawn_template` (0x00430AF0).

    The plan lists:
      - every creature allocated and configured directly by the template
      - any spawn-slot configurations (deferred child spawns)
      - side-effects like burst FX
    """
    pos_x, pos_y = pos

    # creature_alloc_slot() for the base creature.
    creatures: list[CreatureInit] = [_alloc_creature(template_id, pos_x, pos_y, rng)]
    spawn_slots: list[SpawnSlotInit] = []
    effects: list[BurstEffect] = []
    primary_idx = 0

    # `heading == -100.0` uses a randomized heading.
    final_heading = heading
    if final_heading == -100.0:
        final_heading = float(rng.rand() % 0x274) * 0.01

    # Base initialization always consumes one rand() for a transient heading value.
    creatures[0].heading = float(rng.rand() % 0x13A) * 0.01

    if template_id == 0x00:
        c = creatures[0]
        c.type_id = CreatureTypeId.ZOMBIE
        c.flags = CreatureFlags.ANIM_PING_PONG | CreatureFlags.ANIM_LONG_STRIP
        slot_idx = len(spawn_slots)
        c.spawn_slot = slot_idx
        spawn_slots.append(
            SpawnSlotInit(
                owner_creature=0,
                timer=1.0,
                count=0,
                limit=0x32C,
                interval=0.7,
                child_template_id=0x41,
            )
        )
        c.size = 64.0
        c.health = 8500.0
        c.move_speed = 1.3
        c.reward_value = 6600.0
        c.tint_r = 0.6
        c.tint_g = 0.6
        c.tint_b = 1.0
        c.tint_a = 0.8
        c.contact_damage = 50.0
        primary_idx = 0
    elif template_id == 1:
        c = creatures[0]
        c.type_id = CreatureTypeId.SPIDER_SP2
        c.flags = CreatureFlags.SPLIT_ON_DEATH
        c.size = 80.0
        c.health = 400.0
        c.move_speed = 2.0
        c.reward_value = 1000.0
        c.tint_a = 1.0
        c.tint_r = 0.8
        c.tint_g = 0.7
        c.tint_b = 0.4
        c.contact_damage = 17.0
        primary_idx = 0
    elif template_id == 0x03:
        c = creatures[0]
        c.type_id = CreatureTypeId.SPIDER_SP1
        size = float(rng.rand() % 0xF + 0x26)
        c.size = size
        c.health = size * (8.0 / 7.0) + 20.0
        c.tint_a = 1.0
        c.tint_r = 0.6
        c.tint_g = 0.6
        c.move_speed = float(rng.rand() % 0x12) * 0.1 + 1.1
        c.reward_value = size + size + 50.0
        tint_b = float(rng.rand() % 0x19) * 0.01 + 0.8
        c.tint_b = min(max(tint_b, 0.0), 1.0)
        c.contact_damage = float(rng.rand() % 10) + 4.0
        primary_idx = 0
    elif template_id == 0x04:
        c = creatures[0]
        c.type_id = CreatureTypeId.LIZARD
        size = float(rng.rand() % 0xF + 0x26)
        c.size = size
        c.health = size * (8.0 / 7.0) + 20.0
        c.tint_a = 1.0
        c.tint_r = 0.67
        c.tint_g = 0.67
        c.tint_b = 1.0
        c.move_speed = float(rng.rand() % 0x12) * 0.1 + 1.1
        c.reward_value = size + size + 50.0
        c.contact_damage = float(rng.rand() % 10) + 4.0
        primary_idx = 0
    elif template_id == 0x05:
        c = creatures[0]
        c.type_id = CreatureTypeId.SPIDER_SP2
        size = float(rng.rand() % 0xF + 0x26)
        c.size = size
        c.health = size * (8.0 / 7.0) + 20.0
        c.tint_a = 1.0
        c.tint_r = 0.6
        c.tint_g = 0.6
        c.move_speed = float(rng.rand() % 0x12) * 0.1 + 1.1
        c.reward_value = size + size + 50.0
        tint_b = float(rng.rand() % 0x19) * 0.01 + 0.8
        c.tint_b = min(max(tint_b, 0.0), 1.0)
        c.contact_damage = float(rng.rand() % 10) + 4.0
        primary_idx = 0
    elif template_id == 0x06:
        c = creatures[0]
        c.type_id = CreatureTypeId.ALIEN
        size = float(rng.rand() % 0xF + 0x26)
        c.size = size
        c.health = size * (8.0 / 7.0) + 20.0
        c.tint_a = 1.0
        c.tint_r = 0.6
        c.tint_g = 0.6
        c.move_speed = float(rng.rand() % 0x12) * 0.1 + 1.1
        c.reward_value = size + size + 50.0
        tint_b = float(rng.rand() % 0x19) * 0.01 + 0.8
        c.tint_b = min(max(tint_b, 0.0), 1.0)
        c.contact_damage = float(rng.rand() % 10) + 4.0
        primary_idx = 0
    elif template_id in (0x07, 0x08):
        c = creatures[0]
        c.type_id = CreatureTypeId.ALIEN
        c.flags = CreatureFlags.ANIM_PING_PONG
        slot_idx = len(spawn_slots)
        c.spawn_slot = slot_idx
        interval = 2.2 if template_id == 0x07 else 2.8
        spawn_slots.append(
            SpawnSlotInit(
                owner_creature=0,
                timer=1.0,
                count=0,
                limit=100,
                interval=interval,
                child_template_id=0x1D,
            )
        )
        c.size = 50.0
        c.health = 1000.0
        c.move_speed = 2.0
        c.reward_value = 3000.0
        c.tint_a = 1.0
        c.tint_r = 1.0
        c.tint_g = 1.0
        c.tint_b = 1.0
        c.contact_damage = 0.0
        primary_idx = 0
    elif template_id == 0x09:
        c = creatures[0]
        c.type_id = CreatureTypeId.ALIEN
        c.flags = CreatureFlags.ANIM_PING_PONG
        slot_idx = len(spawn_slots)
        c.spawn_slot = slot_idx
        spawn_slots.append(
            SpawnSlotInit(
                owner_creature=0,
                timer=1.0,
                count=0,
                limit=0x10,
                interval=2.0,
                child_template_id=0x1D,
            )
        )
        c.size = 40.0
        c.health = 450.0
        c.move_speed = 2.0
        c.reward_value = 1000.0
        c.tint_a = 1.0
        c.tint_r = 1.0
        c.tint_g = 1.0
        c.tint_b = 1.0
        c.contact_damage = 0.0
        primary_idx = 0
    elif template_id == 0x0A:
        c = creatures[0]
        c.type_id = CreatureTypeId.ALIEN
        c.flags = CreatureFlags.ANIM_PING_PONG
        slot_idx = len(spawn_slots)
        c.spawn_slot = slot_idx
        spawn_slots.append(
            SpawnSlotInit(
                owner_creature=0,
                timer=2.0,
                count=0,
                limit=100,
                interval=5.0,
                child_template_id=0x32,
            )
        )
        c.size = 55.0
        c.health = 1000.0
        c.move_speed = 1.5
        c.reward_value = 3000.0
        c.tint_a = 1.0
        c.tint_r = 0.8
        c.tint_g = 0.7
        c.tint_b = 0.4
        c.contact_damage = 0.0
        primary_idx = 0
    elif template_id == 0x0B:
        c = creatures[0]
        c.type_id = CreatureTypeId.ALIEN
        c.flags = CreatureFlags.ANIM_PING_PONG
        slot_idx = len(spawn_slots)
        c.spawn_slot = slot_idx
        spawn_slots.append(
            SpawnSlotInit(
                owner_creature=0,
                timer=2.0,
                count=0,
                limit=100,
                interval=6.0,
                child_template_id=0x3C,
            )
        )
        c.size = 65.0
        c.health = 3500.0
        c.move_speed = 1.5
        c.reward_value = 5000.0
        c.tint_a = 1.0
        c.tint_r = 0.9
        c.tint_g = 0.1
        c.tint_b = 0.1
        c.contact_damage = 0.0
        primary_idx = 0
    elif template_id == 0x0C:
        c = creatures[0]
        c.type_id = CreatureTypeId.ALIEN
        c.flags = CreatureFlags.ANIM_PING_PONG
        slot_idx = len(spawn_slots)
        c.spawn_slot = slot_idx
        spawn_slots.append(
            SpawnSlotInit(
                owner_creature=0,
                timer=1.5,
                count=0,
                limit=100,
                interval=2.0,
                child_template_id=0x31,
            )
        )
        c.size = 32.0
        c.health = 50.0
        c.move_speed = 2.8
        c.reward_value = 1000.0
        # Shared "alien spawner" tail for this branch sets these (before LAB_004310b8).
        c.tint_a = 1.0
        c.tint_r = 0.9
        c.tint_g = 0.8
        c.tint_b = 0.4
        c.contact_damage = 0.0
        primary_idx = 0
    elif template_id == 0x0D:
        c = creatures[0]
        c.type_id = CreatureTypeId.ALIEN
        c.flags = CreatureFlags.ANIM_PING_PONG
        slot_idx = len(spawn_slots)
        c.spawn_slot = slot_idx
        spawn_slots.append(
            SpawnSlotInit(
                owner_creature=0,
                timer=2.0,
                count=0,
                limit=100,
                interval=6.0,
                child_template_id=0x31,
            )
        )
        c.size = 32.0
        c.health = 50.0
        c.move_speed = 1.3
        c.reward_value = 1000.0
        # Shared "alien spawner" tail for this branch sets these (before LAB_004310b8).
        c.tint_a = 1.0
        c.tint_r = 0.9
        c.tint_g = 0.8
        c.tint_b = 0.4
        c.contact_damage = 0.0
        primary_idx = 0
    elif template_id == 0x10:
        c = creatures[0]
        c.type_id = CreatureTypeId.ALIEN
        c.flags = CreatureFlags.ANIM_PING_PONG
        slot_idx = len(spawn_slots)
        c.spawn_slot = slot_idx
        spawn_slots.append(
            SpawnSlotInit(
                owner_creature=0,
                timer=1.5,
                count=0,
                limit=100,
                interval=2.3,
                child_template_id=0x32,
            )
        )
        c.size = 32.0
        c.health = 50.0
        c.move_speed = 2.8
        c.reward_value = 800.0
        # Shared "alien spawner" tail for this branch sets these (before LAB_004310b8).
        c.tint_a = 1.0
        c.tint_r = 0.9
        c.tint_g = 0.8
        c.tint_b = 0.4
        c.contact_damage = 0.0
        primary_idx = 0
    elif template_id == 0x0E:
        parent = creatures[0]
        parent.type_id = CreatureTypeId.ALIEN
        parent.flags = CreatureFlags.ANIM_PING_PONG
        slot_idx = len(spawn_slots)
        parent.spawn_slot = slot_idx
        spawn_slots.append(
            SpawnSlotInit(
                owner_creature=0,
                timer=1.5,
                count=0,
                limit=0x40,
                interval=1.05,
                child_template_id=0x1C,
            )
        )
        parent.size = 32.0
        parent.health = 50.0
        parent.move_speed = 2.8
        parent.reward_value = 5000.0
        parent.tint_a = 1.0
        parent.tint_r = 0.9
        parent.tint_g = 0.8
        parent.tint_b = 0.4
        parent.contact_damage = 0.0

        for i in range(0x18):
            child = _alloc_creature(template_id, pos_x, pos_y, rng)
            child.ai_mode = 3
            child.ai_link_parent = 0
            child.heading = 0.0
            child.phase_seed = 0.0  # template overwrites anim_phase to 0.0
            angle = float(i) * (math.pi / 12.0)
            child.target_offset_x = float(math.cos(angle) * 100.0)
            child.target_offset_y = float(math.sin(angle) * 100.0)
            child.tint_r = 1.0
            child.tint_g = 0.3
            child.tint_b = 0.3
            child.tint_a = 1.0
            child.health = 40.0
            child.max_health = 40.0
            child.type_id = CreatureTypeId.ALIEN
            child.move_speed = 4.0
            child.reward_value = 350.0
            child.size = 35.0
            child.contact_damage = 30.0
            creatures.append(child)

        primary_idx = len(creatures) - 1
    elif template_id == 0x0F:
        c = creatures[0]
        c.type_id = CreatureTypeId.ALIEN
        c.tint_r = 0.665
        c.tint_g = 0.385
        c.tint_b = 0.259
        c.tint_a = 0.56
        c.health = 20.0
        c.move_speed = 2.9
        c.reward_value = 60.0
        c.size = 50.0
        c.contact_damage = 35.0
        primary_idx = 0
    elif template_id == 0x11:
        parent = creatures[0]
        parent.type_id = CreatureTypeId.LIZARD
        parent.ai_mode = 1
        parent.tint_r = 0.99
        parent.tint_g = 0.99
        parent.tint_b = 0.21
        parent.tint_a = 1.0
        parent.health = 1500.0
        parent.max_health = 1500.0
        parent.move_speed = 2.1
        parent.reward_value = 1000.0
        parent.size = 69.0
        parent.contact_damage = 150.0

        # Spawns a linked chain of 4 children (link points to previous). The original also sets
        # the base creature's link_index to the last child after the loop.
        chain_prev = 0
        local_48 = 2
        for i in range(4):
            child = _alloc_creature(template_id, pos_x, pos_y, rng)
            child.ai_mode = 3
            child.ai_link_parent = chain_prev
            child.target_offset_x = -256.0 + float(i) * 64.0
            child.target_offset_y = -256.0
            angle = float(local_48) * (math.pi / 8.0)
            child.pos_x = float(math.cos(angle) * 256.0 + pos_x)
            child.pos_y = float(math.sin(angle) * 256.0 + pos_y)
            child.tint_r = 0.6
            child.tint_g = 0.6
            child.tint_b = 0.31
            child.tint_a = 1.0
            child.health = 60.0
            child.max_health = 60.0
            child.reward_value = 60.0
            child.type_id = CreatureTypeId.LIZARD
            child.move_speed = 2.4
            child.size = 50.0
            child.contact_damage = 14.0
            creatures.append(child)
            chain_prev = len(creatures) - 1
            local_48 += 2

        parent.ai_link_parent = chain_prev
        primary_idx = chain_prev
        _apply_unhandled_creature_type_fallback(creatures, primary_idx)
    elif template_id == 0x12:
        parent = creatures[0]
        parent.type_id = CreatureTypeId.ALIEN
        parent.tint_r = 0.65
        parent.tint_g = 0.85
        parent.tint_b = 0.97
        parent.tint_a = 1.0
        parent.health = 200.0
        parent.max_health = 200.0
        parent.move_speed = 2.2
        parent.reward_value = 600.0
        parent.size = 55.0
        parent.contact_damage = 14.0

        # Spawns 8 linked orbiters in a ring (step ~= pi/4).
        for i in range(8):
            child = _alloc_creature(template_id, pos_x, pos_y, rng)
            child.ai_mode = 3
            child.ai_link_parent = 0
            angle = float(i) * (math.pi / 4.0)
            child.target_offset_x = float(math.cos(angle) * 100.0)
            child.target_offset_y = float(math.sin(angle) * 100.0)
            child.tint_r = 0.32
            child.tint_g = 0.588
            child.tint_b = 0.426
            child.tint_a = 1.0
            child.health = 40.0
            child.max_health = 40.0
            child.type_id = CreatureTypeId.ALIEN
            child.move_speed = 2.4
            child.reward_value = 60.0
            child.size = 50.0
            child.contact_damage = 4.0
            creatures.append(child)

        # The original function returns the last allocated creature pointer.
        primary_idx = len(creatures) - 1
        _apply_unhandled_creature_type_fallback(creatures, primary_idx)
    elif template_id == 0x13:
        parent = creatures[0]
        parent.type_id = CreatureTypeId.ALIEN
        parent.ai_mode = 6
        parent.pos_x = pos_x + 256.0
        parent.pos_y = pos_y
        parent.tint_r = 0.6
        parent.tint_g = 0.8
        parent.tint_b = 0.91
        parent.tint_a = 1.0
        parent.health = 200.0
        parent.max_health = 200.0
        parent.move_speed = 2.0
        parent.reward_value = 600.0
        parent.size = 40.0
        parent.contact_damage = 20.0

        chain_prev = 0
        for i in range(2, 0x16, 2):
            child = _alloc_creature(template_id, pos_x, pos_y, rng)
            child.ai_mode = 6
            child.ai_link_parent = chain_prev
            child.orbit_angle = math.pi
            child.orbit_radius = 10.0
            angle = float(i) * math.radians(20.0)
            child.pos_x = float(math.cos(angle) * 256.0 + pos_x)
            child.pos_y = float(math.sin(angle) * 256.0 + pos_y)
            child.tint_r = 0.4
            child.tint_g = 0.7
            child.tint_b = 0.11
            child.tint_a = 1.0
            child.health = 60.0
            child.max_health = 60.0
            child.type_id = CreatureTypeId.ALIEN
            child.move_speed = 2.0
            child.reward_value = 60.0
            child.size = 50.0
            child.contact_damage = 4.0
            creatures.append(child)
            chain_prev = len(creatures) - 1

        parent.ai_link_parent = chain_prev
        primary_idx = len(creatures) - 1
        _apply_unhandled_creature_type_fallback(creatures, primary_idx)
    elif template_id == 0x14:
        parent = creatures[0]
        parent.type_id = CreatureTypeId.ALIEN
        parent.ai_mode = 2
        parent.tint_r = 0.7
        parent.tint_g = 0.8
        parent.tint_b = 0.31
        parent.tint_a = 1.0
        parent.health = 1500.0
        parent.max_health = 1500.0
        parent.move_speed = 2.0
        parent.reward_value = 600.0
        parent.size = 50.0
        parent.contact_damage = 40.0

        for x_offset in range(0, -0x240, -0x40):
            for y_offset in range(0x80, 0x101, 0x10):
                child = _alloc_creature(template_id, pos_x, pos_y, rng)
                child.ai_mode = 5
                child.ai_link_parent = 0
                child.target_offset_x = float(x_offset)
                child.target_offset_y = float(y_offset)
                child.pos_x = float(pos_x + x_offset)
                child.pos_y = float(pos_y + y_offset)
                child.tint_r = 0.4
                child.tint_g = 0.7
                child.tint_b = 0.11
                child.tint_a = 1.0
                child.health = 40.0
                child.max_health = 40.0
                child.type_id = CreatureTypeId.ALIEN
                child.move_speed = 2.0
                child.reward_value = 60.0
                child.size = 50.0
                child.contact_damage = 4.0
                creatures.append(child)

        primary_idx = len(creatures) - 1
        _apply_unhandled_creature_type_fallback(creatures, primary_idx)
    elif template_id == 0x15:
        parent = creatures[0]
        parent.type_id = CreatureTypeId.ALIEN
        parent.ai_mode = 2
        parent.tint_r = 1.0
        parent.tint_g = 1.0
        parent.tint_b = 1.0
        parent.tint_a = 1.0
        parent.health = 1500.0
        parent.max_health = 1500.0
        parent.move_speed = 2.0
        parent.reward_value = 600.0
        parent.size = 60.0
        parent.contact_damage = 40.0

        for x_offset in range(0, -0x240, -0x40):
            for y_offset in range(0x80, 0x101, 0x10):
                child = _alloc_creature(template_id, pos_x, pos_y, rng)
                child.ai_mode = 4
                child.ai_link_parent = 0
                child.target_offset_x = float(x_offset)
                child.target_offset_y = float(y_offset)
                child.pos_x = float(pos_x + x_offset)
                child.pos_y = float(pos_y + y_offset)
                child.tint_r = 0.4
                child.tint_g = 0.7
                child.tint_b = 0.11
                child.tint_a = 1.0
                child.health = 40.0
                child.max_health = 40.0
                child.type_id = CreatureTypeId.ALIEN
                child.move_speed = 2.0
                child.reward_value = 60.0
                child.size = 50.0
                child.contact_damage = 4.0
                creatures.append(child)

        primary_idx = len(creatures) - 1
        _apply_unhandled_creature_type_fallback(creatures, primary_idx)
    elif template_id == 0x16:
        parent = creatures[0]
        parent.type_id = CreatureTypeId.LIZARD
        parent.ai_mode = 2
        parent.tint_r = 1.0
        parent.tint_g = 1.0
        parent.tint_b = 1.0
        parent.tint_a = 1.0
        parent.health = 1500.0
        parent.max_health = 1500.0
        parent.move_speed = 2.0
        parent.reward_value = 600.0
        parent.size = 64.0
        parent.contact_damage = 40.0

        for x_offset in range(0, -0x240, -0x40):
            for y_offset in range(0x80, 0x101, 0x10):
                child = _alloc_creature(template_id, pos_x, pos_y, rng)
                child.ai_mode = 4
                child.ai_link_parent = 0
                child.target_offset_x = float(x_offset)
                child.target_offset_y = float(y_offset)
                child.pos_x = float(pos_x + x_offset)
                child.pos_y = float(pos_y + y_offset)
                child.tint_r = 0.4
                child.tint_g = 0.7
                child.tint_b = 0.11
                child.tint_a = 1.0
                child.health = 40.0
                child.max_health = 40.0
                child.type_id = CreatureTypeId.LIZARD
                child.move_speed = 2.0
                child.reward_value = 60.0
                child.size = 60.0
                child.contact_damage = 4.0
                creatures.append(child)

        primary_idx = len(creatures) - 1
        _apply_unhandled_creature_type_fallback(creatures, primary_idx)
    elif template_id == 0x17:
        parent = creatures[0]
        parent.type_id = CreatureTypeId.SPIDER_SP1
        parent.ai_mode = 2
        parent.tint_r = 1.0
        parent.tint_g = 1.0
        parent.tint_b = 1.0
        parent.tint_a = 1.0
        parent.health = 1500.0
        parent.max_health = 1500.0
        parent.move_speed = 2.0
        parent.reward_value = 600.0
        parent.size = 60.0
        parent.contact_damage = 40.0

        for x_offset in range(0, -0x240, -0x40):
            for y_offset in range(0x80, 0x101, 0x10):
                child = _alloc_creature(template_id, pos_x, pos_y, rng)
                child.ai_mode = 4
                child.ai_link_parent = 0
                child.target_offset_x = float(x_offset)
                child.target_offset_y = float(y_offset)
                child.pos_x = float(pos_x + x_offset)
                child.pos_y = float(pos_y + y_offset)
                child.tint_r = 0.4
                child.tint_g = 0.7
                child.tint_b = 0.11
                child.tint_a = 1.0
                child.health = 40.0
                child.max_health = 40.0
                child.type_id = CreatureTypeId.SPIDER_SP1
                child.move_speed = 2.0
                child.reward_value = 60.0
                child.size = 50.0
                child.contact_damage = 4.0
                creatures.append(child)

        primary_idx = len(creatures) - 1
        _apply_unhandled_creature_type_fallback(creatures, primary_idx)
    elif template_id == 0x18:
        parent = creatures[0]
        parent.type_id = CreatureTypeId.ALIEN
        parent.ai_mode = 2
        parent.tint_r = 0.7
        parent.tint_g = 0.8
        parent.tint_b = 0.31
        parent.tint_a = 1.0
        parent.health = 500.0
        parent.max_health = 500.0
        parent.move_speed = 2.0
        parent.reward_value = 600.0
        parent.size = 40.0
        parent.contact_damage = 40.0

        for x_offset in range(0, -0x240, -0x40):
            for y_offset in range(0x80, 0x101, 0x10):
                child = _alloc_creature(template_id, pos_x, pos_y, rng)
                child.ai_mode = 3
                child.ai_link_parent = 0
                child.target_offset_x = float(x_offset)
                child.target_offset_y = float(y_offset)
                child.pos_x = float(pos_x + x_offset)
                child.pos_y = float(pos_y + y_offset)
                child.tint_r = 0.7125
                child.tint_g = 0.4125
                child.tint_b = 0.2775
                child.tint_a = 0.6
                child.health = 260.0
                child.max_health = 260.0
                child.type_id = CreatureTypeId.ALIEN
                child.move_speed = 3.8
                child.reward_value = 60.0
                child.size = 50.0
                child.contact_damage = 35.0
                creatures.append(child)

        primary_idx = len(creatures) - 1
        _apply_unhandled_creature_type_fallback(creatures, primary_idx)
    elif template_id == 0x19:
        parent = creatures[0]
        parent.type_id = CreatureTypeId.ALIEN
        parent.tint_r = 0.95
        parent.tint_g = 0.55
        parent.tint_b = 0.37
        parent.tint_a = 1.0
        parent.health = 50.0
        parent.max_health = 50.0
        parent.move_speed = 3.8
        parent.reward_value = 300.0
        parent.size = 55.0
        parent.contact_damage = 40.0

        for i in range(5):
            child = _alloc_creature(template_id, pos_x, pos_y, rng)
            child.ai_mode = 5
            child.ai_link_parent = 0
            angle = float(i) * (math.tau / 5.0)
            child.target_offset_x = float(math.cos(angle) * 110.0)
            child.target_offset_y = float(math.sin(angle) * 110.0)
            child.pos_x = pos_x + (child.target_offset_x or 0.0)
            child.pos_y = pos_y + (child.target_offset_y or 0.0)
            child.tint_r = 0.7125
            child.tint_g = 0.4125
            child.tint_b = 0.2775
            child.tint_a = 0.6
            child.health = 220.0
            child.max_health = 220.0
            child.type_id = CreatureTypeId.ALIEN
            child.move_speed = 3.8
            child.reward_value = 60.0
            child.size = 50.0
            child.contact_damage = 35.0
            creatures.append(child)

        primary_idx = len(creatures) - 1
        _apply_unhandled_creature_type_fallback(creatures, primary_idx)
    elif template_id in (0x1A, 0x1B, 0x1C):
        c = creatures[0]
        c.ai_mode = 1
        c.size = 50.0
        c.move_speed = 2.4
        c.reward_value = 125.0
        c.tint_a = 1.0

        if template_id == 0x1A:
            c.type_id = CreatureTypeId.ALIEN
            c.health = 50.0
        elif template_id == 0x1B:
            c.type_id = CreatureTypeId.SPIDER_SP1
            c.health = 40.0
        else:
            c.type_id = CreatureTypeId.LIZARD
            c.health = 50.0

        tint = float(rng.rand() % 40) * 0.01 + 0.5
        c.tint_r = tint
        c.tint_g = tint
        c.tint_b = 1.0
        c.contact_damage = 5.0
        primary_idx = 0
    elif template_id == 0x1D:
        c = creatures[0]
        c.type_id = CreatureTypeId.ALIEN
        size = float(rng.rand() % 20 + 35)
        c.size = size
        c.health = size * (8.0 / 7.0) + 10.0
        c.move_speed = float(rng.rand() % 15) * 0.1 + 1.1
        c.reward_value = float(rng.rand() % 100 + 50)
        c.tint_a = 1.0
        c.tint_r = float(rng.rand() % 50) * 0.001 + 0.6
        c.tint_g = float(rng.rand() % 50) * 0.01 + 0.5
        c.tint_b = float(rng.rand() % 50) * 0.001 + 0.6
        c.contact_damage = float(rng.rand() % 10) + 4.0
        primary_idx = 0
    elif template_id == 0x1E:
        c = creatures[0]
        c.type_id = CreatureTypeId.ALIEN
        size = float(rng.rand() % 30 + 35)
        c.size = size
        c.health = size * (16.0 / 7.0) + 10.0
        c.move_speed = float(rng.rand() % 17) * 0.1 + 1.5
        c.reward_value = float(rng.rand() % 200 + 50)
        c.tint_a = 1.0
        c.tint_r = float(rng.rand() % 50) * 0.001 + 0.6
        c.tint_g = float(rng.rand() % 50) * 0.001 + 0.6
        c.tint_b = float(rng.rand() % 50) * 0.01 + 0.5
        c.contact_damage = float(rng.rand() % 30) + 4.0
        primary_idx = 0
    elif template_id == 0x1F:
        c = creatures[0]
        c.type_id = CreatureTypeId.ALIEN
        size = float(rng.rand() % 30 + 45)
        c.size = size
        c.health = size * (26.0 / 7.0) + 30.0
        c.move_speed = float(rng.rand() % 21) * 0.1 + 1.6
        c.reward_value = float(rng.rand() % 200 + 80)
        c.tint_a = 1.0
        c.tint_r = float(rng.rand() % 50) * 0.01 + 0.5
        c.tint_g = float(rng.rand() % 50) * 0.001 + 0.6
        c.tint_b = float(rng.rand() % 50) * 0.001 + 0.6
        c.contact_damage = float(rng.rand() % 35) + 8.0
        primary_idx = 0
    elif template_id == 0x20:
        c = creatures[0]
        c.type_id = CreatureTypeId.ALIEN
        size = float(rng.rand() % 30 + 40)
        c.size = size
        c.health = size * (8.0 / 7.0) + 20.0
        c.tint_a = 1.0
        c.tint_r = 0.3
        c.move_speed = float(rng.rand() % 18) * 0.1 + 1.1
        c.reward_value = size + size + 50.0
        c.tint_b = 0.3
        c.tint_g = float(rng.rand() % 40) * 0.01 + 0.6
        c.contact_damage = float(rng.rand() % 10) + 4.0
        primary_idx = 0
    elif template_id == 0x21:
        c = creatures[0]
        c.type_id = CreatureTypeId.ALIEN
        c.health = 53.0
        c.move_speed = 1.7
        c.reward_value = 120.0
        c.tint_r = 0.7
        c.tint_g = 0.1
        c.tint_b = 0.51
        c.tint_a = 0.5
        c.size = 55.0
        c.contact_damage = 8.0
        primary_idx = 0
    elif template_id == 0x22:
        c = creatures[0]
        c.type_id = CreatureTypeId.ALIEN
        c.health = 25.0
        c.move_speed = 1.7
        c.reward_value = 150.0
        c.tint_r = 0.1
        c.tint_g = 0.7
        c.tint_b = 0.51
        c.tint_a = 0.05
        c.size = 50.0
        c.contact_damage = 8.0
        primary_idx = 0
    elif template_id == 0x23:
        c = creatures[0]
        c.type_id = CreatureTypeId.ALIEN
        c.health = 5.0
        c.move_speed = 1.7
        c.reward_value = 180.0
        c.tint_r = 0.1
        c.tint_g = 0.7
        c.tint_b = 0.51
        c.tint_a = 0.04
        c.size = 45.0
        c.contact_damage = 8.0
        primary_idx = 0
    # Demo (attract-mode) templates.
    elif template_id == 0x24:
        c = creatures[0]
        c.type_id = CreatureTypeId.ALIEN
        c.health = 20.0
        c.move_speed = 2.0
        c.reward_value = 110.0
        c.tint_r = 0.1
        c.tint_g = 0.7
        c.tint_b = 0.11
        c.tint_a = 1.0
        c.size = 50.0
        c.contact_damage = 4.0
        primary_idx = 0
    elif template_id == 0x25:
        c = creatures[0]
        c.type_id = CreatureTypeId.ALIEN
        c.health = 25.0
        c.move_speed = 2.5
        c.reward_value = 125.0
        c.tint_r = 0.1
        c.tint_g = 0.8
        c.tint_b = 0.11
        c.tint_a = 1.0
        c.size = 30.0
        c.contact_damage = 3.0
        primary_idx = 0
    elif template_id == 0x26:
        c = creatures[0]
        c.type_id = CreatureTypeId.ALIEN
        c.health = 50.0
        c.move_speed = 2.2
        c.reward_value = 125.0
        c.tint_r = 0.6
        c.tint_g = 0.8
        c.tint_b = 0.6
        c.tint_a = 1.0
        c.size = 45.0
        c.contact_damage = 10.0
        primary_idx = 0
    elif template_id == 0x27:
        c = creatures[0]
        c.type_id = CreatureTypeId.ALIEN
        c.flags = CreatureFlags.BONUS_ON_DEATH
        c.health = 50.0
        c.move_speed = 2.1
        c.reward_value = 125.0
        c.tint_r = 1.0
        c.tint_g = 0.8
        c.tint_b = 0.1
        c.tint_a = 1.0
        c.size = 45.0
        c.contact_damage = 10.0
        primary_idx = 0
    elif template_id == 0x28:
        c = creatures[0]
        c.type_id = CreatureTypeId.ALIEN
        c.health = 50.0
        c.move_speed = 1.7
        c.reward_value = 150.0
        c.tint_r = 0.7
        c.tint_g = 0.1
        c.tint_b = 0.51
        c.tint_a = 1.0
        c.size = 55.0
        c.contact_damage = 8.0
        primary_idx = 0
    elif template_id == 0x29:
        c = creatures[0]
        c.type_id = CreatureTypeId.ALIEN
        c.health = 800.0
        c.move_speed = 2.5
        c.reward_value = 450.0
        c.tint_r = 0.8
        c.tint_g = 0.8
        c.tint_b = 0.8
        c.tint_a = 1.0
        c.size = 70.0
        c.contact_damage = 20.0
        primary_idx = 0
    elif template_id == 0x2A:
        c = creatures[0]
        c.type_id = CreatureTypeId.ALIEN
        c.health = 50.0
        c.move_speed = 3.1
        c.reward_value = 300.0
        c.tint_r = 0.3
        c.tint_g = 0.3
        c.tint_b = 0.3
        c.tint_a = 1.0
        c.size = 60.0
        c.contact_damage = 8.0
        primary_idx = 0
    elif template_id == 0x2B:
        c = creatures[0]
        c.type_id = CreatureTypeId.ALIEN
        c.health = 30.0
        c.move_speed = 3.6
        c.reward_value = 450.0
        c.tint_r = 1.0
        c.tint_g = 0.3
        c.tint_b = 0.3
        c.tint_a = 1.0
        c.size = 35.0
        c.contact_damage = 20.0
        primary_idx = 0
    elif template_id == 0x2C:
        c = creatures[0]
        c.type_id = CreatureTypeId.ALIEN
        c.health = 3800.0
        c.move_speed = 2.0
        c.reward_value = 1500.0
        c.tint_r = 0.85
        c.tint_g = 0.2
        c.tint_b = 0.2
        c.tint_a = 1.0
        c.size = 80.0
        c.contact_damage = 40.0
        primary_idx = 0
    elif template_id == 0x2D:
        c = creatures[0]
        c.type_id = CreatureTypeId.ALIEN
        c.ai_mode = 2
        c.health = 45.0
        c.move_speed = 3.1
        c.reward_value = 200.0
        c.tint_r = 0.0
        c.tint_g = 0.9
        c.tint_b = 0.8
        c.tint_a = 1.0
        c.size = 38.0
        c.contact_damage = 3.0
        primary_idx = 0
    elif template_id == 0x2E:
        c = creatures[0]
        c.type_id = CreatureTypeId.LIZARD
        size = float(rng.rand() % 0x1E + 0x28)
        c.size = size
        c.health = size * (8.0 / 7.0) + 20.0
        c.tint_a = 1.0
        c.move_speed = float(rng.rand() % 0x12) * 0.1 + 1.1
        c.reward_value = size + size + 50.0
        c.tint_r = float(rng.rand() % 0x28) * 0.01 + 0.6
        c.tint_g = float(rng.rand() % 0x28) * 0.01 + 0.6
        c.tint_b = float(rng.rand() % 0x28) * 0.01 + 0.6
        c.contact_damage = float(rng.rand() % 10) + 4.0
        primary_idx = 0
    elif template_id == 0x2F:
        c = creatures[0]
        c.type_id = CreatureTypeId.LIZARD
        c.health = 20.0
        c.move_speed = 2.5
        c.reward_value = 150.0
        c.tint_r = 0.8
        c.tint_g = 0.8
        c.tint_b = 0.8
        c.tint_a = 1.0
        c.size = 45.0
        c.contact_damage = 4.0
        primary_idx = 0
    elif template_id == 0x30:
        c = creatures[0]
        c.type_id = CreatureTypeId.LIZARD
        c.health = 1000.0
        c.move_speed = 2.0
        c.reward_value = 400.0
        c.tint_r = 0.9
        c.tint_g = 0.8
        c.tint_b = 0.1
        c.tint_a = 1.0
        c.size = 65.0
        c.contact_damage = 10.0
        primary_idx = 0
    elif template_id == 0x31:
        c = creatures[0]
        c.type_id = CreatureTypeId.LIZARD
        size = float(rng.rand() % 0x1E + 0x28)
        c.size = size
        c.health = size * (8.0 / 7.0) + 10.0
        c.tint_a = 1.0
        c.move_speed = float(rng.rand() % 0x12) * 0.1 + 1.1
        c.reward_value = size + size + 50.0
        tint = float(rng.rand() % 0x1E) * 0.01 + 0.6
        c.tint_r = tint
        c.tint_g = tint
        c.tint_b = 0.38
        c.contact_damage = size * 0.14 + 4.0
        primary_idx = 0
    elif template_id == 0x32:
        c = creatures[0]
        c.type_id = CreatureTypeId.SPIDER_SP1
        size = float(rng.rand() % 0x19 + 0x28)
        c.size = size
        c.health = size + 10.0
        c.tint_a = 1.0
        c.move_speed = float(rng.rand() % 0x11) * 0.1 + 1.1
        c.reward_value = size + size + 50.0
        tint = float(rng.rand() % 0x28) * 0.01 + 0.6
        c.tint_r = tint
        c.tint_g = tint
        c.tint_b = tint
        c.contact_damage = size * 0.14 + 4.0
        primary_idx = 0
    elif template_id == 0x33:
        c = creatures[0]
        c.type_id = CreatureTypeId.SPIDER_SP1
        size = float(rng.rand() % 0xF + 0x2D)
        c.size = size
        c.health = size * (8.0 / 7.0) + 20.0
        c.tint_a = 1.0
        c.move_speed = float(rng.rand() % 0x12) * 0.1 + 1.1
        c.reward_value = size + size + 50.0
        c.tint_g = 0.5
        c.tint_b = 0.5
        c.tint_r = float(rng.rand() % 0x28) * 0.01 + 0.6
        c.contact_damage = float(rng.rand() % 10) + 4.0
        primary_idx = 0
    elif template_id == 0x34:
        c = creatures[0]
        c.type_id = CreatureTypeId.SPIDER_SP1
        c.size = float(rng.rand() % 0x14 + 0x28)
        c.health = float((c.size or 0.0) * (8.0 / 7.0) + 20.0)
        c.tint_a = 1.0
        c.move_speed = float(rng.rand() % 0x12) * 0.1 + 1.1
        c.reward_value = float((c.size or 0.0) + (c.size or 0.0) + 50.0)
        c.tint_r = 0.5
        c.tint_b = 0.5
        c.tint_g = float(rng.rand() % 0x28) * 0.01 + 0.6
        c.contact_damage = float(rng.rand() % 10) + 4.0
        primary_idx = 0
    elif template_id == 0x35:
        c = creatures[0]
        c.type_id = CreatureTypeId.SPIDER_SP2
        c.size = float(rng.rand() % 10 + 0x1E)
        c.health = float((c.size or 0.0) * (8.0 / 7.0) + 20.0)
        c.tint_a = 1.0
        c.tint_b = 0.8
        c.move_speed = float(rng.rand() % 0x12) * 0.1 + 1.1
        c.reward_value = float((c.size or 0.0) + (c.size or 0.0) + 50.0)
        c.tint_r = 0.8
        c.tint_g = float(rng.rand() % 0x14) * 0.01 + 0.8
        c.contact_damage = float(rng.rand() % 10) + 4.0
        primary_idx = 0
    elif template_id == 0x36:
        c = creatures[0]
        c.type_id = CreatureTypeId.ALIEN
        c.size = 50.0
        c.ai_mode = 7
        c.orbit_radius = 1.5
        c.health = 10.0
        c.move_speed = 1.8
        c.reward_value = 150.0
        c.tint_a = 1.0
        c.tint_g = float(rng.rand() % 5) * 0.01 + 0.65
        c.tint_r = 0.65
        c.tint_b = 0.95
        c.contact_damage = 40.0
        primary_idx = 0
    elif template_id == 0x37:
        c = creatures[0]
        c.type_id = CreatureTypeId.SPIDER_SP2
        c.flags = CreatureFlags.RANGED_ATTACK_VARIANT
        c.health = 50.0
        c.move_speed = 3.2
        c.reward_value = 433.0
        c.tint_r = 1.0
        c.tint_g = 0.75
        c.tint_b = 0.1
        c.tint_a = 1.0
        c.size = float((rng.rand() & 3) + 0x29)
        c.contact_damage = 10.0
        primary_idx = 0
    elif template_id == 0x38:
        c = creatures[0]
        c.type_id = CreatureTypeId.SPIDER_SP1
        c.flags = CreatureFlags.AI7_LINK_TIMER
        c.ai_timer = 0
        c.health = 50.0
        c.move_speed = 4.8
        c.reward_value = 433.0
        c.tint_r = 1.0
        c.tint_g = 0.75
        c.tint_b = 0.1
        c.tint_a = 1.0
        c.size = float((rng.rand() & 3) + 0x29)
        c.contact_damage = 10.0
        primary_idx = 0
    elif template_id == 0x39:
        c = creatures[0]
        c.type_id = CreatureTypeId.SPIDER_SP1
        c.flags = CreatureFlags.AI7_LINK_TIMER
        c.ai_timer = 0
        c.health = 4.0
        c.move_speed = 4.8
        c.reward_value = 50.0
        c.tint_r = 0.8
        c.tint_g = 0.65
        c.tint_b = 0.1
        c.tint_a = 1.0
        c.size = float(rng.rand() % 4 + 26)
        c.contact_damage = 10.0
        primary_idx = 0
    elif template_id == 0x3A:
        c = creatures[0]
        c.type_id = CreatureTypeId.SPIDER_SP1
        c.flags = CreatureFlags.RANGED_ATTACK_SHOCK
        c.orbit_angle = 0.9
        c.ranged_projectile_type = 9
        c.health = 4500.0
        c.move_speed = 2.0
        c.reward_value = 4500.0
        c.tint_r = 1.0
        c.tint_g = 1.0
        c.tint_b = 1.0
        c.tint_a = 1.0
        c.size = 64.0
        c.contact_damage = 50.0
        primary_idx = 0
    elif template_id == 0x3B:
        c = creatures[0]
        c.type_id = CreatureTypeId.SPIDER_SP1
        c.health = 1200.0
        c.move_speed = 2.0
        c.reward_value = 4000.0
        c.tint_r = 0.9
        c.tint_g = 0.0
        c.tint_b = 0.0
        c.tint_a = 1.0
        c.size = 70.0
        c.contact_damage = 20.0
        primary_idx = 0
    elif template_id == 0x3C:
        c = creatures[0]
        c.type_id = CreatureTypeId.SPIDER_SP1
        c.flags = CreatureFlags.RANGED_ATTACK_VARIANT
        c.orbit_angle = 0.4
        c.ranged_projectile_type = 26
        c.health = 200.0
        c.move_speed = 2.0
        c.reward_value = 200.0
        c.tint_r = 0.9
        c.tint_g = 0.1
        c.tint_b = 0.1
        c.tint_a = 1.0
        c.size = 40.0
        c.contact_damage = 20.0
        c.ai_mode = 2
        primary_idx = 0
    elif template_id == 0x3D:
        c = creatures[0]
        c.type_id = CreatureTypeId.SPIDER_SP1
        c.health = 70.0
        c.move_speed = 2.6
        c.reward_value = 120.0
        c.tint_a = 1.0
        tint = float(rng.rand() % 20) * 0.01 + 0.8
        c.tint_r = tint
        c.tint_g = tint
        c.tint_b = tint
        size = float(rng.rand() % 7 + 45)
        c.size = size
        c.contact_damage = size * 0.22
        primary_idx = 0
    elif template_id == 0x3E:
        c = creatures[0]
        c.type_id = CreatureTypeId.SPIDER_SP1
        c.health = 1000.0
        c.move_speed = 2.8
        c.reward_value = 500.0
        c.tint_r = 1.0
        c.tint_g = 1.0
        c.tint_b = 1.0
        c.tint_a = 1.0
        c.size = 64.0
        c.contact_damage = 40.0
        primary_idx = 0
    elif template_id == 0x3F:
        c = creatures[0]
        c.type_id = CreatureTypeId.SPIDER_SP1
        c.health = 200.0
        c.move_speed = 2.3
        c.reward_value = 210.0
        c.tint_r = 0.7
        c.tint_g = 0.4
        c.tint_b = 0.1
        c.tint_a = 1.0
        c.size = 35.0
        c.contact_damage = 20.0
        primary_idx = 0
    elif template_id == 0x40:
        c = creatures[0]
        c.type_id = CreatureTypeId.SPIDER_SP1
        c.health = 70.0
        c.move_speed = 2.2
        c.reward_value = 160.0
        c.tint_r = 0.5
        c.tint_g = 0.6
        c.tint_b = 0.9
        c.tint_a = 1.0
        c.size = 45.0
        c.contact_damage = 5.0
        primary_idx = 0
    elif template_id == 0x41:
        c = creatures[0]
        c.type_id = CreatureTypeId.ZOMBIE
        c.tint_a = 1.0
        c.size = float(rng.rand() % 0x1E + 0x28)
        c.health = float((c.size or 0.0) * (8.0 / 7.0) + 10.0)
        c.move_speed = float((c.size or 0.0) * 0.0025 + 0.9)
        c.reward_value = float((c.size or 0.0) + (c.size or 0.0) + 50.0)
        tint = float(rng.rand() % 0x28) * 0.01 + 0.6
        c.tint_r = tint
        c.tint_g = tint
        c.tint_b = tint
        c.contact_damage = float(rng.rand() % 10) + 4.0
        primary_idx = 0
    elif template_id == 0x42:
        c = creatures[0]
        c.type_id = CreatureTypeId.ZOMBIE
        c.health = 200.0
        c.move_speed = 1.7
        c.reward_value = 160.0
        c.tint_r = 0.9
        c.tint_g = 0.9
        c.tint_b = 0.9
        c.tint_a = 1.0
        c.size = 45.0
        c.contact_damage = 15.0
        primary_idx = 0
    elif template_id == 0x43:
        c = creatures[0]
        c.type_id = CreatureTypeId.ZOMBIE
        c.health = 2000.0
        c.move_speed = 2.1
        c.reward_value = 460.0
        c.tint_r = 0.2
        c.tint_g = 0.6
        c.tint_b = 0.1
        c.tint_a = 1.0
        c.size = 70.0
        c.contact_damage = 15.0
        primary_idx = 0
    else:
        raise NotImplementedError(f"spawn plan not implemented for template_id=0x{template_id:x}")

    _apply_tail(
        template_id=template_id,
        plan_creatures=creatures,
        plan_spawn_slots=spawn_slots,
        plan_effects=effects,
        primary_idx=primary_idx,
        final_heading=final_heading,
        env=env,
    )
    return SpawnPlan(
        creatures=tuple(creatures),
        spawn_slots=tuple(spawn_slots),
        effects=tuple(effects),
        primary=primary_idx,
    )
