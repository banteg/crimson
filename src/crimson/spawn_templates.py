from __future__ import annotations

"""Spawn template ids extracted from creature_spawn_template (FUN_00430af0).

Hand-maintained (promoted from static analysis). Run `uv run python scripts/gen_spawn_templates.py`
to regenerate the docs table in `docs/structs/creature.md`.
"""

from dataclasses import dataclass
from enum import IntEnum, IntFlag


class CreatureTypeId(IntEnum):
    ZOMBIE = 0
    LIZARD = 1
    ALIEN = 2
    SPIDER_SP1 = 3
    SPIDER_SP2 = 4
    TROOPER = 5


class CreatureFlags(IntFlag):
    SELF_DAMAGE_TICK = 0x01  # periodic self-damage tick (dt * 60)
    SELF_DAMAGE_TICK_STRONG = 0x02  # stronger self-damage tick (dt * 180)
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
        flags=CreatureFlags.ANIM_PING_PONG,
        creature="alien",
        anim_note="short strip (ping-pong)",
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
        flags=CreatureFlags.ANIM_PING_PONG,
        creature="alien",
        anim_note="short strip (ping-pong)",
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
        type_id=CreatureTypeId.ALIEN,
        flags=CreatureFlags.RANGED_ATTACK_SHOCK,
        creature="alien",
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
