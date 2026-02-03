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
from typing import Callable, SupportsInt

from ..bonuses import BonusId
from grim.rand import Crand

__all__ = [
    "BurstEffect",
    "CreatureFlags",
    "CreatureInfFlag",
    "CreatureInit",
    "CreatureTypeId",
    "SpawnId",
    "SPAWN_ID_TO_TEMPLATE",
    "SPAWN_TEMPLATES",
    "SpawnEnv",
    "SpawnPlan",
    "SpawnSlotInit",
    "SpawnTemplate",
    "SpawnTemplateCall",
    "TYPE_ID_TO_NAME",
    "advance_survival_spawn_stage",
    "build_rush_mode_spawn_creature",
    "build_spawn_plan",
    "build_survival_spawn_creature",
    "build_tutorial_stage3_fire_spawns",
    "build_tutorial_stage4_clear_spawns",
    "build_tutorial_stage5_repeat_spawns",
    "build_tutorial_stage6_perks_done_spawns",
    "resolve_tint",
    "spawn_id_label",
    "tick_rush_mode_spawns",
    "tick_spawn_slot",
    "tick_survival_wave_spawns",
]

Tint = tuple[float | None, float | None, float | None, float | None]
TintRGBA = tuple[float, float, float, float]


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
    HAS_SPAWN_SLOT = 0x04  # alias: link_index interpreted as spawn slot index
    SPLIT_ON_DEATH = 0x08  # split-on-death behavior
    RANGED_ATTACK_SHOCK = 0x10  # ranged attack using projectile type 9
    ANIM_LONG_STRIP = 0x40  # force long animation strip
    AI7_LINK_TIMER = 0x80  # uses link index as timer for AI mode 7
    RANGED_ATTACK_VARIANT = 0x100  # ranged attack using orbit_radius as projectile type
    BONUS_ON_DEATH = 0x400  # spawns bonus on death


class CreatureInfFlag(IntFlag):
    """Low-byte creature infection flags.

    This corresponds to the native `collision_flag` byte in `creature_t`.
    """

    INFECTED = 0x01


class SpawnId(IntEnum):
    ZOMBIE_BOSS_SPAWNER_00 = 0x00
    SPIDER_SP2_SPLITTER_01 = 0x01
    UNUSED_02 = 0x02
    SPIDER_SP1_RANDOM_03 = 0x03
    LIZARD_RANDOM_04 = 0x04
    SPIDER_SP2_RANDOM_05 = 0x05
    ALIEN_RANDOM_06 = 0x06

    ALIEN_SPAWNER_CHILD_1D_FAST_07 = 0x07
    ALIEN_SPAWNER_CHILD_1D_SLOW_08 = 0x08
    ALIEN_SPAWNER_CHILD_1D_LIMITED_09 = 0x09
    ALIEN_SPAWNER_CHILD_32_SLOW_0A = 0x0A
    ALIEN_SPAWNER_CHILD_3C_SLOW_0B = 0x0B
    ALIEN_SPAWNER_CHILD_31_FAST_0C = 0x0C
    ALIEN_SPAWNER_CHILD_31_SLOW_0D = 0x0D
    ALIEN_SPAWNER_RING_24_0E = 0x0E
    ALIEN_CONST_BROWN_TRANSPARENT_0F = 0x0F
    ALIEN_SPAWNER_CHILD_32_FAST_10 = 0x10

    FORMATION_CHAIN_LIZARD_4_11 = 0x11
    FORMATION_RING_ALIEN_8_12 = 0x12
    FORMATION_CHAIN_ALIEN_10_13 = 0x13
    FORMATION_GRID_ALIEN_GREEN_14 = 0x14
    FORMATION_GRID_ALIEN_WHITE_15 = 0x15
    FORMATION_GRID_LIZARD_WHITE_16 = 0x16
    FORMATION_GRID_SPIDER_SP1_WHITE_17 = 0x17
    FORMATION_GRID_ALIEN_BRONZE_18 = 0x18
    FORMATION_RING_ALIEN_5_19 = 0x19

    AI1_ALIEN_BLUE_TINT_1A = 0x1A
    AI1_SPIDER_SP1_BLUE_TINT_1B = 0x1B
    AI1_LIZARD_BLUE_TINT_1C = 0x1C

    ALIEN_RANDOM_1D = 0x1D
    ALIEN_RANDOM_1E = 0x1E
    ALIEN_RANDOM_1F = 0x1F
    ALIEN_RANDOM_GREEN_20 = 0x20

    ALIEN_CONST_PURPLE_GHOST_21 = 0x21
    ALIEN_CONST_GREEN_GHOST_22 = 0x22
    ALIEN_CONST_GREEN_GHOST_SMALL_23 = 0x23
    ALIEN_CONST_GREEN_24 = 0x24
    ALIEN_CONST_GREEN_SMALL_25 = 0x25
    ALIEN_CONST_PALE_GREEN_26 = 0x26
    ALIEN_CONST_WEAPON_BONUS_27 = 0x27
    ALIEN_CONST_PURPLE_28 = 0x28
    ALIEN_CONST_GREY_BRUTE_29 = 0x29
    ALIEN_CONST_GREY_FAST_2A = 0x2A
    ALIEN_CONST_RED_FAST_2B = 0x2B
    ALIEN_CONST_RED_BOSS_2C = 0x2C
    ALIEN_CONST_CYAN_AI2_2D = 0x2D

    LIZARD_RANDOM_2E = 0x2E
    LIZARD_CONST_GREY_2F = 0x2F
    LIZARD_CONST_YELLOW_BOSS_30 = 0x30
    LIZARD_RANDOM_31 = 0x31

    SPIDER_SP1_RANDOM_32 = 0x32
    SPIDER_SP1_RANDOM_RED_33 = 0x33
    SPIDER_SP1_RANDOM_GREEN_34 = 0x34
    SPIDER_SP2_RANDOM_35 = 0x35

    ALIEN_AI7_ORBITER_36 = 0x36
    SPIDER_SP2_RANGED_VARIANT_37 = 0x37
    SPIDER_SP1_AI7_TIMER_38 = 0x38
    SPIDER_SP1_AI7_TIMER_WEAK_39 = 0x39

    SPIDER_SP1_CONST_SHOCK_BOSS_3A = 0x3A
    SPIDER_SP1_CONST_RED_BOSS_3B = 0x3B
    SPIDER_SP1_CONST_RANGED_VARIANT_3C = 0x3C
    SPIDER_SP1_RANDOM_3D = 0x3D
    SPIDER_SP1_CONST_WHITE_FAST_3E = 0x3E
    SPIDER_SP1_CONST_BROWN_SMALL_3F = 0x3F
    SPIDER_SP1_CONST_BLUE_40 = 0x40

    ZOMBIE_RANDOM_41 = 0x41
    ZOMBIE_CONST_GREY_42 = 0x42
    ZOMBIE_CONST_GREEN_BRUTE_43 = 0x43


@dataclass(frozen=True, slots=True)
class SpawnTemplate:
    spawn_id: SpawnId
    type_id: CreatureTypeId | None
    flags: CreatureFlags | None
    creature: str | None
    anim_note: str | None
    tint: Tint | None = None
    size: float | None = None
    move_speed: float | None = None


TYPE_ID_TO_NAME = {type_id.value: type_id.name.lower() for type_id in CreatureTypeId}

# For many template ids, tint/size/move_speed are randomized or derived from other fields.
# We only fill them in when the game uses fixed constants (and keep the rest as `None`).
SPAWN_TEMPLATES = [
    SpawnTemplate(
        spawn_id=SpawnId.ZOMBIE_BOSS_SPAWNER_00,
        type_id=CreatureTypeId.ZOMBIE,
        flags=CreatureFlags.ANIM_PING_PONG | CreatureFlags.ANIM_LONG_STRIP,
        creature="zombie",
        anim_note="long strip (0x40 overrides 0x4)",
        tint=(0.6, 0.6, 1.0, 0.8),
        size=64.0,
        move_speed=1.3,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.SPIDER_SP2_SPLITTER_01,
        type_id=CreatureTypeId.SPIDER_SP2,
        flags=CreatureFlags.SPLIT_ON_DEATH,
        creature="spider_sp2",
        anim_note=None,
        tint=(0.8, 0.7, 0.4, 1.0),
        size=80.0,
        move_speed=2.0,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.SPIDER_SP1_RANDOM_03,
        type_id=CreatureTypeId.SPIDER_SP1,
        flags=None,
        creature="spider_sp1",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.LIZARD_RANDOM_04,
        type_id=CreatureTypeId.LIZARD,
        flags=None,
        creature="lizard",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.SPIDER_SP2_RANDOM_05,
        type_id=CreatureTypeId.SPIDER_SP2,
        flags=None,
        creature="spider_sp2",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ALIEN_RANDOM_06,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_1D_FAST_07,
        type_id=CreatureTypeId.ALIEN,
        flags=CreatureFlags.ANIM_PING_PONG,
        creature="alien",
        anim_note="short strip (ping-pong)",
        tint=(1.0, 1.0, 1.0, 1.0),
        size=50.0,
        move_speed=2.0,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_1D_SLOW_08,
        type_id=CreatureTypeId.ALIEN,
        flags=CreatureFlags.ANIM_PING_PONG,
        creature="alien",
        anim_note="short strip (ping-pong)",
        tint=(1.0, 1.0, 1.0, 1.0),
        size=50.0,
        move_speed=2.0,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_1D_LIMITED_09,
        type_id=CreatureTypeId.ALIEN,
        flags=CreatureFlags.ANIM_PING_PONG,
        creature="alien",
        anim_note="short strip (ping-pong)",
        tint=(1.0, 1.0, 1.0, 1.0),
        size=40.0,
        move_speed=2.0,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_32_SLOW_0A,
        type_id=CreatureTypeId.ALIEN,
        flags=CreatureFlags.ANIM_PING_PONG,
        creature="alien",
        anim_note="short strip (ping-pong)",
        tint=(0.8, 0.7, 0.4, 1.0),
        size=55.0,
        move_speed=1.5,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_3C_SLOW_0B,
        type_id=CreatureTypeId.ALIEN,
        flags=CreatureFlags.ANIM_PING_PONG,
        creature="alien",
        anim_note="short strip (ping-pong)",
        tint=(0.9, 0.1, 0.1, 1.0),
        size=65.0,
        move_speed=1.5,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_31_FAST_0C,
        type_id=CreatureTypeId.ALIEN,
        flags=CreatureFlags.ANIM_PING_PONG,
        creature="alien",
        anim_note="short strip (ping-pong)",
        tint=(0.9, 0.8, 0.4, 1.0),
        size=32.0,
        move_speed=2.8,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_31_SLOW_0D,
        type_id=CreatureTypeId.ALIEN,
        flags=CreatureFlags.ANIM_PING_PONG,
        creature="alien",
        anim_note="short strip (ping-pong)",
        tint=(0.9, 0.8, 0.4, 1.0),
        size=32.0,
        move_speed=1.3,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ALIEN_SPAWNER_RING_24_0E,
        type_id=CreatureTypeId.ALIEN,
        flags=CreatureFlags.ANIM_PING_PONG,
        creature="alien",
        anim_note="short strip (ping-pong)",
        tint=(0.9, 0.8, 0.4, 1.0),
        size=32.0,
        move_speed=2.8,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ALIEN_CONST_BROWN_TRANSPARENT_0F,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
        tint=(0.665, 0.385, 0.259, 0.56),
        size=50.0,
        move_speed=2.9,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ALIEN_SPAWNER_CHILD_32_FAST_10,
        type_id=CreatureTypeId.ALIEN,
        flags=CreatureFlags.ANIM_PING_PONG,
        creature="alien",
        anim_note="short strip (ping-pong)",
        tint=(0.9, 0.8, 0.4, 1.0),
        size=32.0,
        move_speed=2.8,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.FORMATION_CHAIN_LIZARD_4_11,
        type_id=CreatureTypeId.LIZARD,
        flags=None,
        creature="lizard",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.FORMATION_RING_ALIEN_8_12,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.FORMATION_CHAIN_ALIEN_10_13,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.FORMATION_GRID_ALIEN_GREEN_14,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.FORMATION_GRID_ALIEN_WHITE_15,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.FORMATION_GRID_LIZARD_WHITE_16,
        type_id=CreatureTypeId.LIZARD,
        flags=None,
        creature="lizard",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.FORMATION_GRID_SPIDER_SP1_WHITE_17,
        type_id=CreatureTypeId.SPIDER_SP1,
        flags=None,
        creature="spider_sp1",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.FORMATION_GRID_ALIEN_BRONZE_18,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.FORMATION_RING_ALIEN_5_19,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.AI1_ALIEN_BLUE_TINT_1A,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.AI1_SPIDER_SP1_BLUE_TINT_1B,
        type_id=CreatureTypeId.SPIDER_SP1,
        flags=None,
        creature="spider_sp1",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.AI1_LIZARD_BLUE_TINT_1C,
        type_id=CreatureTypeId.LIZARD,
        flags=None,
        creature="lizard",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ALIEN_RANDOM_1D,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ALIEN_RANDOM_1E,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ALIEN_RANDOM_1F,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ALIEN_RANDOM_GREEN_20,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ALIEN_CONST_PURPLE_GHOST_21,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ALIEN_CONST_GREEN_GHOST_22,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ALIEN_CONST_GREEN_GHOST_SMALL_23,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ALIEN_CONST_GREEN_24,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
        tint=(0.1, 0.7, 0.11, 1.0),
        size=50.0,
        move_speed=2.0,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ALIEN_CONST_GREEN_SMALL_25,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
        tint=(0.1, 0.8, 0.11, 1.0),
        size=30.0,
        move_speed=2.5,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ALIEN_CONST_PALE_GREEN_26,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
        tint=(0.6, 0.8, 0.6, 1.0),
        size=45.0,
        move_speed=2.2,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ALIEN_CONST_WEAPON_BONUS_27,
        type_id=CreatureTypeId.ALIEN,
        flags=CreatureFlags.BONUS_ON_DEATH,
        creature="alien",
        anim_note="bonus_id=WEAPON (3), duration_override=5 (packed in link_index)",
        tint=(1.0, 0.8, 0.1, 1.0),
        size=45.0,
        move_speed=2.1,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ALIEN_CONST_PURPLE_28,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
        tint=(0.7, 0.1, 0.51, 1.0),
        size=55.0,
        move_speed=1.7,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ALIEN_CONST_GREY_BRUTE_29,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
        tint=(0.8, 0.8, 0.8, 1.0),
        size=70.0,
        move_speed=2.5,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ALIEN_CONST_GREY_FAST_2A,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
        tint=(0.3, 0.3, 0.3, 1.0),
        size=60.0,
        move_speed=3.1,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ALIEN_CONST_RED_FAST_2B,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
        tint=(1.0, 0.3, 0.3, 1.0),
        size=35.0,
        move_speed=3.6,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ALIEN_CONST_RED_BOSS_2C,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
        tint=(0.85, 0.2, 0.2, 1.0),
        size=80.0,
        move_speed=2.0,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ALIEN_CONST_CYAN_AI2_2D,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
        tint=(0.0, 0.9, 0.8, 1.0),
        size=38.0,
        move_speed=3.1,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.LIZARD_RANDOM_2E,
        type_id=CreatureTypeId.LIZARD,
        flags=None,
        creature="lizard",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.LIZARD_CONST_GREY_2F,
        type_id=CreatureTypeId.LIZARD,
        flags=None,
        creature="lizard",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.LIZARD_CONST_YELLOW_BOSS_30,
        type_id=CreatureTypeId.LIZARD,
        flags=None,
        creature="lizard",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.LIZARD_RANDOM_31,
        type_id=CreatureTypeId.LIZARD,
        flags=None,
        creature="lizard",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.SPIDER_SP1_RANDOM_32,
        type_id=CreatureTypeId.SPIDER_SP1,
        flags=None,
        creature="spider_sp1",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.SPIDER_SP1_RANDOM_RED_33,
        type_id=CreatureTypeId.SPIDER_SP1,
        flags=None,
        creature="spider_sp1",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.SPIDER_SP1_RANDOM_GREEN_34,
        type_id=CreatureTypeId.SPIDER_SP1,
        flags=None,
        creature="spider_sp1",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.SPIDER_SP2_RANDOM_35,
        type_id=CreatureTypeId.SPIDER_SP2,
        flags=None,
        creature="spider_sp2",
        anim_note=None,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ALIEN_AI7_ORBITER_36,
        type_id=CreatureTypeId.ALIEN,
        flags=None,
        creature="alien",
        anim_note=None,
        tint=(0.65, None, 0.95, 1.0),
        size=50.0,
        move_speed=1.8,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.SPIDER_SP2_RANGED_VARIANT_37,
        type_id=CreatureTypeId.SPIDER_SP2,
        flags=CreatureFlags.RANGED_ATTACK_VARIANT,
        creature="spider_sp2",
        anim_note=None,
        tint=(1.0, 0.75, 0.1, 1.0),
        move_speed=3.2,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.SPIDER_SP1_AI7_TIMER_38,
        type_id=CreatureTypeId.SPIDER_SP1,
        flags=CreatureFlags.AI7_LINK_TIMER,
        creature="spider_sp1",
        anim_note=None,
        tint=(1.0, 0.75, 0.1, 1.0),
        move_speed=4.8,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.SPIDER_SP1_AI7_TIMER_WEAK_39,
        type_id=CreatureTypeId.SPIDER_SP1,
        flags=CreatureFlags.AI7_LINK_TIMER,
        creature="spider_sp1",
        anim_note=None,
        tint=(0.8, 0.65, 0.1, 1.0),
        move_speed=4.8,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.SPIDER_SP1_CONST_SHOCK_BOSS_3A,
        type_id=CreatureTypeId.SPIDER_SP1,
        flags=CreatureFlags.RANGED_ATTACK_SHOCK,
        creature="spider_sp1",
        anim_note="projectile_type=9",
        tint=(1.0, 1.0, 1.0, 1.0),
        size=64.0,
        move_speed=2.0,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.SPIDER_SP1_CONST_RED_BOSS_3B,
        type_id=CreatureTypeId.SPIDER_SP1,
        flags=None,
        creature="spider_sp1",
        anim_note=None,
        tint=(0.9, 0.0, 0.0, 1.0),
        size=70.0,
        move_speed=2.0,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.SPIDER_SP1_CONST_RANGED_VARIANT_3C,
        type_id=CreatureTypeId.SPIDER_SP1,
        flags=CreatureFlags.RANGED_ATTACK_VARIANT,
        creature="spider_sp1",
        anim_note="projectile_type=26 (packed in orbit_radius)",
        tint=(0.9, 0.1, 0.1, 1.0),
        size=40.0,
        move_speed=2.0,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.SPIDER_SP1_RANDOM_3D,
        type_id=CreatureTypeId.SPIDER_SP1,
        flags=None,
        creature="spider_sp1",
        anim_note=None,
        tint=(None, None, None, 1.0),
        move_speed=2.6,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.SPIDER_SP1_CONST_WHITE_FAST_3E,
        type_id=CreatureTypeId.SPIDER_SP1,
        flags=None,
        creature="spider_sp1",
        anim_note=None,
        tint=(1.0, 1.0, 1.0, 1.0),
        size=64.0,
        move_speed=2.8,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.SPIDER_SP1_CONST_BROWN_SMALL_3F,
        type_id=CreatureTypeId.SPIDER_SP1,
        flags=None,
        creature="spider_sp1",
        anim_note=None,
        tint=(0.7, 0.4, 0.1, 1.0),
        size=35.0,
        move_speed=2.3,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.SPIDER_SP1_CONST_BLUE_40,
        type_id=CreatureTypeId.SPIDER_SP1,
        flags=None,
        creature="spider_sp1",
        anim_note=None,
        tint=(0.5, 0.6, 0.9, 1.0),
        size=45.0,
        move_speed=2.2,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ZOMBIE_RANDOM_41,
        type_id=CreatureTypeId.ZOMBIE,
        flags=None,
        creature="zombie",
        anim_note=None,
        tint=(None, None, None, 1.0),
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ZOMBIE_CONST_GREY_42,
        type_id=CreatureTypeId.ZOMBIE,
        flags=None,
        creature="zombie",
        anim_note=None,
        tint=(0.9, 0.9, 0.9, 1.0),
        size=45.0,
        move_speed=1.7,
    ),
    SpawnTemplate(
        spawn_id=SpawnId.ZOMBIE_CONST_GREEN_BRUTE_43,
        type_id=CreatureTypeId.ZOMBIE,
        flags=None,
        creature="zombie",
        anim_note=None,
        tint=(0.2, 0.6, 0.1, 1.0),
        size=70.0,
        move_speed=2.1,
    ),
]

SPAWN_ID_TO_TEMPLATE = {entry.spawn_id: entry for entry in SPAWN_TEMPLATES}


@dataclass(frozen=True, slots=True)
class AlienSpawnerSpec:
    timer: float
    limit: int
    interval: float
    child_template_id: int
    size: float
    health: float
    move_speed: float
    reward_value: float
    tint: TintRGBA


ALIEN_SPAWNER_TEMPLATES: dict[int, AlienSpawnerSpec] = {
    SpawnId.ALIEN_SPAWNER_CHILD_1D_FAST_07: AlienSpawnerSpec(
        timer=1.0,
        limit=100,
        interval=2.2,
        child_template_id=SpawnId.ALIEN_RANDOM_1D,
        size=50.0,
        health=1000.0,
        move_speed=2.0,
        reward_value=3000.0,
        tint=(1.0, 1.0, 1.0, 1.0),
    ),
    SpawnId.ALIEN_SPAWNER_CHILD_1D_SLOW_08: AlienSpawnerSpec(
        timer=1.0,
        limit=100,
        interval=2.8,
        child_template_id=SpawnId.ALIEN_RANDOM_1D,
        size=50.0,
        health=1000.0,
        move_speed=2.0,
        reward_value=3000.0,
        tint=(1.0, 1.0, 1.0, 1.0),
    ),
    SpawnId.ALIEN_SPAWNER_CHILD_1D_LIMITED_09: AlienSpawnerSpec(
        timer=1.0,
        limit=16,
        interval=2.0,
        child_template_id=SpawnId.ALIEN_RANDOM_1D,
        size=40.0,
        health=450.0,
        move_speed=2.0,
        reward_value=1000.0,
        tint=(1.0, 1.0, 1.0, 1.0),
    ),
    SpawnId.ALIEN_SPAWNER_CHILD_32_SLOW_0A: AlienSpawnerSpec(
        timer=2.0,
        limit=100,
        interval=5.0,
        child_template_id=SpawnId.SPIDER_SP1_RANDOM_32,
        size=55.0,
        health=1000.0,
        move_speed=1.5,
        reward_value=3000.0,
        tint=(0.8, 0.7, 0.4, 1.0),
    ),
    SpawnId.ALIEN_SPAWNER_CHILD_3C_SLOW_0B: AlienSpawnerSpec(
        timer=2.0,
        limit=100,
        interval=6.0,
        child_template_id=SpawnId.SPIDER_SP1_CONST_RANGED_VARIANT_3C,
        size=65.0,
        health=3500.0,
        move_speed=1.5,
        reward_value=5000.0,
        tint=(0.9, 0.1, 0.1, 1.0),
    ),
    SpawnId.ALIEN_SPAWNER_CHILD_31_FAST_0C: AlienSpawnerSpec(
        timer=1.5,
        limit=100,
        interval=2.0,
        child_template_id=SpawnId.LIZARD_RANDOM_31,
        size=32.0,
        health=50.0,
        move_speed=2.8,
        reward_value=1000.0,
        tint=(0.9, 0.8, 0.4, 1.0),
    ),
    SpawnId.ALIEN_SPAWNER_CHILD_31_SLOW_0D: AlienSpawnerSpec(
        timer=2.0,
        limit=100,
        interval=6.0,
        child_template_id=SpawnId.LIZARD_RANDOM_31,
        size=32.0,
        health=50.0,
        move_speed=1.3,
        reward_value=1000.0,
        tint=(0.9, 0.8, 0.4, 1.0),
    ),
    SpawnId.ALIEN_SPAWNER_CHILD_32_FAST_10: AlienSpawnerSpec(
        timer=1.5,
        limit=100,
        interval=2.3,
        child_template_id=SpawnId.SPIDER_SP1_RANDOM_32,
        size=32.0,
        health=50.0,
        move_speed=2.8,
        reward_value=800.0,
        tint=(0.9, 0.8, 0.4, 1.0),
    ),
}


@dataclass(frozen=True, slots=True)
class ConstantSpawnSpec:
    type_id: CreatureTypeId
    health: float
    move_speed: float
    reward_value: float
    tint: TintRGBA
    size: float
    contact_damage: float
    flags: CreatureFlags = CreatureFlags(0)
    ai_mode: int = 0
    orbit_angle: float | None = None
    orbit_radius: float | None = None
    ranged_projectile_type: int | None = None
    bonus_id: BonusId | None = None
    bonus_duration_override: int | None = None


@dataclass(frozen=True, slots=True)
class FormationChildSpec:
    type_id: CreatureTypeId
    health: float
    move_speed: float
    reward_value: float
    size: float
    contact_damage: float
    tint: TintRGBA
    max_health: float | None = None
    orbit_angle: float | None = None
    orbit_radius: float | None = None


@dataclass(frozen=True, slots=True)
class GridFormationSpec:
    parent: ConstantSpawnSpec
    child_ai_mode: int
    child_spec: FormationChildSpec
    x_range: range
    y_range: range
    apply_fallback: bool = False
    set_parent_max_health: bool = True


@dataclass(frozen=True, slots=True)
class RingFormationSpec:
    parent: ConstantSpawnSpec
    child_ai_mode: int
    child_spec: FormationChildSpec
    count: int
    angle_step: float
    radius: float
    apply_fallback: bool = False
    set_position: bool = False
    set_parent_max_health: bool = True


CONSTANT_SPAWN_TEMPLATES: dict[int, ConstantSpawnSpec] = {
    SpawnId.SPIDER_SP2_SPLITTER_01: ConstantSpawnSpec(
        type_id=CreatureTypeId.SPIDER_SP2,
        health=400.0,
        move_speed=2.0,
        reward_value=1000.0,
        tint=(0.8, 0.7, 0.4, 1.0),
        size=80.0,
        contact_damage=17.0,
        flags=CreatureFlags.SPLIT_ON_DEATH,
    ),
    SpawnId.ALIEN_CONST_BROWN_TRANSPARENT_0F: ConstantSpawnSpec(
        type_id=CreatureTypeId.ALIEN,
        health=20.0,
        move_speed=2.9,
        reward_value=60.0,
        tint=(0.665, 0.385, 0.259, 0.56),
        size=50.0,
        contact_damage=35.0,
    ),
    SpawnId.ALIEN_CONST_PURPLE_GHOST_21: ConstantSpawnSpec(
        type_id=CreatureTypeId.ALIEN,
        health=53.0,
        move_speed=1.7,
        reward_value=120.0,
        tint=(0.7, 0.1, 0.51, 0.5),
        size=55.0,
        contact_damage=8.0,
    ),
    SpawnId.ALIEN_CONST_GREEN_GHOST_22: ConstantSpawnSpec(
        type_id=CreatureTypeId.ALIEN,
        health=25.0,
        move_speed=1.7,
        reward_value=150.0,
        tint=(0.1, 0.7, 0.51, 0.05),
        size=50.0,
        contact_damage=8.0,
    ),
    SpawnId.ALIEN_CONST_GREEN_GHOST_SMALL_23: ConstantSpawnSpec(
        type_id=CreatureTypeId.ALIEN,
        health=5.0,
        move_speed=1.7,
        reward_value=180.0,
        tint=(0.1, 0.7, 0.51, 0.04),
        size=45.0,
        contact_damage=8.0,
    ),
    SpawnId.ALIEN_CONST_GREEN_24: ConstantSpawnSpec(
        type_id=CreatureTypeId.ALIEN,
        health=20.0,
        move_speed=2.0,
        reward_value=110.0,
        tint=(0.1, 0.7, 0.11, 1.0),
        size=50.0,
        contact_damage=4.0,
    ),
    SpawnId.ALIEN_CONST_GREEN_SMALL_25: ConstantSpawnSpec(
        type_id=CreatureTypeId.ALIEN,
        health=25.0,
        move_speed=2.5,
        reward_value=125.0,
        tint=(0.1, 0.8, 0.11, 1.0),
        size=30.0,
        contact_damage=3.0,
    ),
    SpawnId.ALIEN_CONST_PALE_GREEN_26: ConstantSpawnSpec(
        type_id=CreatureTypeId.ALIEN,
        health=50.0,
        move_speed=2.2,
        reward_value=125.0,
        tint=(0.6, 0.8, 0.6, 1.0),
        size=45.0,
        contact_damage=10.0,
    ),
    SpawnId.ALIEN_CONST_WEAPON_BONUS_27: ConstantSpawnSpec(
        type_id=CreatureTypeId.ALIEN,
        health=50.0,
        move_speed=2.1,
        reward_value=125.0,
        tint=(1.0, 0.8, 0.1, 1.0),
        size=45.0,
        contact_damage=10.0,
        flags=CreatureFlags.BONUS_ON_DEATH,
        bonus_id=BonusId.WEAPON,
        bonus_duration_override=5,
    ),
    SpawnId.ALIEN_CONST_PURPLE_28: ConstantSpawnSpec(
        type_id=CreatureTypeId.ALIEN,
        health=50.0,
        move_speed=1.7,
        reward_value=150.0,
        tint=(0.7, 0.1, 0.51, 1.0),
        size=55.0,
        contact_damage=8.0,
    ),
    SpawnId.ALIEN_CONST_GREY_BRUTE_29: ConstantSpawnSpec(
        type_id=CreatureTypeId.ALIEN,
        health=800.0,
        move_speed=2.5,
        reward_value=450.0,
        tint=(0.8, 0.8, 0.8, 1.0),
        size=70.0,
        contact_damage=20.0,
    ),
    SpawnId.ALIEN_CONST_GREY_FAST_2A: ConstantSpawnSpec(
        type_id=CreatureTypeId.ALIEN,
        health=50.0,
        move_speed=3.1,
        reward_value=300.0,
        tint=(0.3, 0.3, 0.3, 1.0),
        size=60.0,
        contact_damage=8.0,
    ),
    SpawnId.ALIEN_CONST_RED_FAST_2B: ConstantSpawnSpec(
        type_id=CreatureTypeId.ALIEN,
        health=30.0,
        move_speed=3.6,
        reward_value=450.0,
        tint=(1.0, 0.3, 0.3, 1.0),
        size=35.0,
        contact_damage=20.0,
    ),
    SpawnId.ALIEN_CONST_RED_BOSS_2C: ConstantSpawnSpec(
        type_id=CreatureTypeId.ALIEN,
        health=3800.0,
        move_speed=2.0,
        reward_value=1500.0,
        tint=(0.85, 0.2, 0.2, 1.0),
        size=80.0,
        contact_damage=40.0,
    ),
    SpawnId.ALIEN_CONST_CYAN_AI2_2D: ConstantSpawnSpec(
        type_id=CreatureTypeId.ALIEN,
        health=45.0,
        move_speed=3.1,
        reward_value=200.0,
        tint=(0.0, 0.9, 0.8, 1.0),
        size=38.0,
        contact_damage=3.0,
        ai_mode=2,
    ),
    SpawnId.LIZARD_CONST_GREY_2F: ConstantSpawnSpec(
        type_id=CreatureTypeId.LIZARD,
        health=20.0,
        move_speed=2.5,
        reward_value=150.0,
        tint=(0.8, 0.8, 0.8, 1.0),
        size=45.0,
        contact_damage=4.0,
    ),
    SpawnId.LIZARD_CONST_YELLOW_BOSS_30: ConstantSpawnSpec(
        type_id=CreatureTypeId.LIZARD,
        health=1000.0,
        move_speed=2.0,
        reward_value=400.0,
        tint=(0.9, 0.8, 0.1, 1.0),
        size=65.0,
        contact_damage=10.0,
    ),
    SpawnId.SPIDER_SP1_CONST_SHOCK_BOSS_3A: ConstantSpawnSpec(
        type_id=CreatureTypeId.SPIDER_SP1,
        health=4500.0,
        move_speed=2.0,
        reward_value=4500.0,
        tint=(1.0, 1.0, 1.0, 1.0),
        size=64.0,
        contact_damage=50.0,
        flags=CreatureFlags.RANGED_ATTACK_SHOCK,
        orbit_angle=0.9,
        ranged_projectile_type=9,
    ),
    SpawnId.SPIDER_SP1_CONST_RED_BOSS_3B: ConstantSpawnSpec(
        type_id=CreatureTypeId.SPIDER_SP1,
        health=1200.0,
        move_speed=2.0,
        reward_value=4000.0,
        tint=(0.9, 0.0, 0.0, 1.0),
        size=70.0,
        contact_damage=20.0,
    ),
    SpawnId.SPIDER_SP1_CONST_RANGED_VARIANT_3C: ConstantSpawnSpec(
        type_id=CreatureTypeId.SPIDER_SP1,
        health=200.0,
        move_speed=2.0,
        reward_value=200.0,
        tint=(0.9, 0.1, 0.1, 1.0),
        size=40.0,
        contact_damage=20.0,
        flags=CreatureFlags.RANGED_ATTACK_VARIANT,
        ai_mode=2,
        orbit_angle=0.4,
        ranged_projectile_type=26,
    ),
    SpawnId.SPIDER_SP1_CONST_WHITE_FAST_3E: ConstantSpawnSpec(
        type_id=CreatureTypeId.SPIDER_SP1,
        health=1000.0,
        move_speed=2.8,
        reward_value=500.0,
        tint=(1.0, 1.0, 1.0, 1.0),
        size=64.0,
        contact_damage=40.0,
    ),
    SpawnId.SPIDER_SP1_CONST_BROWN_SMALL_3F: ConstantSpawnSpec(
        type_id=CreatureTypeId.SPIDER_SP1,
        health=200.0,
        move_speed=2.3,
        reward_value=210.0,
        tint=(0.7, 0.4, 0.1, 1.0),
        size=35.0,
        contact_damage=20.0,
    ),
    SpawnId.SPIDER_SP1_CONST_BLUE_40: ConstantSpawnSpec(
        type_id=CreatureTypeId.SPIDER_SP1,
        health=70.0,
        move_speed=2.2,
        reward_value=160.0,
        tint=(0.5, 0.6, 0.9, 1.0),
        size=45.0,
        contact_damage=5.0,
    ),
    SpawnId.ZOMBIE_CONST_GREY_42: ConstantSpawnSpec(
        type_id=CreatureTypeId.ZOMBIE,
        health=200.0,
        move_speed=1.7,
        reward_value=160.0,
        tint=(0.9, 0.9, 0.9, 1.0),
        size=45.0,
        contact_damage=15.0,
    ),
    SpawnId.ZOMBIE_CONST_GREEN_BRUTE_43: ConstantSpawnSpec(
        type_id=CreatureTypeId.ZOMBIE,
        health=2000.0,
        move_speed=2.1,
        reward_value=460.0,
        tint=(0.2, 0.6, 0.1, 1.0),
        size=70.0,
        contact_damage=15.0,
    ),
}

GRID_FORMATIONS: dict[int, GridFormationSpec] = {
    SpawnId.FORMATION_GRID_ALIEN_GREEN_14: GridFormationSpec(
        parent=ConstantSpawnSpec(
            type_id=CreatureTypeId.ALIEN,
            health=1500.0,
            move_speed=2.0,
            reward_value=600.0,
            tint=(0.7, 0.8, 0.31, 1.0),
            size=50.0,
            contact_damage=40.0,
            ai_mode=2,
        ),
        child_ai_mode=5,
        child_spec=FormationChildSpec(
            type_id=CreatureTypeId.ALIEN,
            health=40.0,
            move_speed=2.0,
            reward_value=60.0,
            size=50.0,
            contact_damage=4.0,
            tint=(0.4, 0.7, 0.11, 1.0),
        ),
        x_range=range(0, -576, -64),
        y_range=range(128, 257, 16),
        apply_fallback=True,
    ),
    SpawnId.FORMATION_GRID_ALIEN_WHITE_15: GridFormationSpec(
        parent=ConstantSpawnSpec(
            type_id=CreatureTypeId.ALIEN,
            health=1500.0,
            move_speed=2.0,
            reward_value=600.0,
            tint=(1.0, 1.0, 1.0, 1.0),
            size=60.0,
            contact_damage=40.0,
            ai_mode=2,
        ),
        child_ai_mode=4,
        child_spec=FormationChildSpec(
            type_id=CreatureTypeId.ALIEN,
            health=40.0,
            move_speed=2.0,
            reward_value=60.0,
            size=50.0,
            contact_damage=4.0,
            tint=(0.4, 0.7, 0.11, 1.0),
        ),
        x_range=range(0, -576, -64),
        y_range=range(128, 257, 16),
        apply_fallback=True,
    ),
    SpawnId.FORMATION_GRID_LIZARD_WHITE_16: GridFormationSpec(
        parent=ConstantSpawnSpec(
            type_id=CreatureTypeId.LIZARD,
            health=1500.0,
            move_speed=2.0,
            reward_value=600.0,
            tint=(1.0, 1.0, 1.0, 1.0),
            size=64.0,
            contact_damage=40.0,
            ai_mode=2,
        ),
        child_ai_mode=4,
        child_spec=FormationChildSpec(
            type_id=CreatureTypeId.LIZARD,
            health=40.0,
            move_speed=2.0,
            reward_value=60.0,
            size=60.0,
            contact_damage=4.0,
            tint=(0.4, 0.7, 0.11, 1.0),
        ),
        x_range=range(0, -576, -64),
        y_range=range(128, 257, 16),
        apply_fallback=True,
    ),
    SpawnId.FORMATION_GRID_SPIDER_SP1_WHITE_17: GridFormationSpec(
        parent=ConstantSpawnSpec(
            type_id=CreatureTypeId.SPIDER_SP1,
            health=1500.0,
            move_speed=2.0,
            reward_value=600.0,
            tint=(1.0, 1.0, 1.0, 1.0),
            size=60.0,
            contact_damage=40.0,
            ai_mode=2,
        ),
        child_ai_mode=4,
        child_spec=FormationChildSpec(
            type_id=CreatureTypeId.SPIDER_SP1,
            health=40.0,
            move_speed=2.0,
            reward_value=60.0,
            size=50.0,
            contact_damage=4.0,
            tint=(0.4, 0.7, 0.11, 1.0),
        ),
        x_range=range(0, -576, -64),
        y_range=range(128, 257, 16),
        apply_fallback=True,
    ),
    SpawnId.FORMATION_GRID_ALIEN_BRONZE_18: GridFormationSpec(
        parent=ConstantSpawnSpec(
            type_id=CreatureTypeId.ALIEN,
            health=500.0,
            move_speed=2.0,
            reward_value=600.0,
            tint=(0.7, 0.8, 0.31, 1.0),
            size=40.0,
            contact_damage=40.0,
            ai_mode=2,
        ),
        child_ai_mode=3,
        child_spec=FormationChildSpec(
            type_id=CreatureTypeId.ALIEN,
            health=260.0,
            move_speed=3.8,
            reward_value=60.0,
            size=50.0,
            contact_damage=35.0,
            tint=(0.7125, 0.4125, 0.2775, 0.6),
        ),
        x_range=range(0, -576, -64),
        y_range=range(128, 257, 16),
    ),
}

RING_FORMATIONS: dict[int, RingFormationSpec] = {
    SpawnId.FORMATION_RING_ALIEN_8_12: RingFormationSpec(
        parent=ConstantSpawnSpec(
            type_id=CreatureTypeId.ALIEN,
            health=200.0,
            move_speed=2.2,
            reward_value=600.0,
            tint=(0.65, 0.85, 0.97, 1.0),
            size=55.0,
            contact_damage=14.0,
        ),
        child_ai_mode=3,
        child_spec=FormationChildSpec(
            type_id=CreatureTypeId.ALIEN,
            health=40.0,
            move_speed=2.4,
            reward_value=60.0,
            size=50.0,
            contact_damage=4.0,
            tint=(0.32, 0.588, 0.426, 1.0),
        ),
        count=8,
        angle_step=math.pi / 4.0,
        radius=100.0,
        apply_fallback=True,
    ),
    SpawnId.FORMATION_RING_ALIEN_5_19: RingFormationSpec(
        parent=ConstantSpawnSpec(
            type_id=CreatureTypeId.ALIEN,
            health=50.0,
            move_speed=3.8,
            reward_value=300.0,
            tint=(0.95, 0.55, 0.37, 1.0),
            size=55.0,
            contact_damage=40.0,
        ),
        child_ai_mode=5,
        child_spec=FormationChildSpec(
            type_id=CreatureTypeId.ALIEN,
            health=220.0,
            move_speed=3.8,
            reward_value=60.0,
            size=50.0,
            contact_damage=35.0,
            tint=(0.7125, 0.4125, 0.2775, 0.6),
        ),
        count=5,
        angle_step=math.tau / 5.0,
        radius=110.0,
        set_position=True,
        apply_fallback=True,
    ),
}


def spawn_id_label(spawn_id: SupportsInt) -> str:
    entry = SPAWN_ID_TO_TEMPLATE.get(int(spawn_id))
    if entry is None or entry.creature is None:
        return "unknown"
    return entry.creature


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

    tint: Tint | None = None

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

    # Spawn slot reference (stored in link_index in the original when flags include HAS_SPAWN_SLOT).
    spawn_slot: int | None = None

    # BONUS_ON_DEATH uses link_index low/high 16-bit fields for bonus spawn args.
    bonus_id: BonusId | None = None
    bonus_duration_override: int | None = None


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


def add_spawn_slot(
    spawn_slots: list[SpawnSlotInit],
    *,
    owner_creature: int,
    timer: float,
    limit: int,
    interval: float,
    child_template_id: int,
) -> int:
    slot_idx = len(spawn_slots)
    spawn_slots.append(
        SpawnSlotInit(
            owner_creature=owner_creature,
            timer=timer,
            count=0,
            limit=limit,
            interval=interval,
            child_template_id=child_template_id,
        )
    )
    return slot_idx


def apply_constant_template(c: CreatureInit, spec: ConstantSpawnSpec) -> None:
    c.type_id = spec.type_id
    c.flags = spec.flags
    c.ai_mode = spec.ai_mode
    c.health = spec.health
    c.move_speed = spec.move_speed
    c.reward_value = spec.reward_value
    apply_tint(c, spec.tint)
    c.size = spec.size
    c.contact_damage = spec.contact_damage
    if spec.orbit_angle is not None:
        c.orbit_angle = spec.orbit_angle
    if spec.orbit_radius is not None:
        c.orbit_radius = spec.orbit_radius
    if spec.ranged_projectile_type is not None:
        c.ranged_projectile_type = spec.ranged_projectile_type
    if spec.bonus_id is not None:
        c.bonus_id = spec.bonus_id
    if spec.bonus_duration_override is not None:
        c.bonus_duration_override = spec.bonus_duration_override


def apply_tint(c: CreatureInit, tint: TintRGBA) -> None:
    c.tint = tint


def resolve_tint(tint: Tint | None) -> TintRGBA:
    """Resolve a partial/optional tint into concrete RGBA multipliers."""
    if tint is None:
        return (1.0, 1.0, 1.0, 1.0)
    tint_r, tint_g, tint_b, tint_a = tint
    return (
        1.0 if tint_r is None else tint_r,
        1.0 if tint_g is None else tint_g,
        1.0 if tint_b is None else tint_b,
        1.0 if tint_a is None else tint_a,
    )


def apply_child_spec(child: CreatureInit, spec: FormationChildSpec) -> None:
    child.type_id = spec.type_id
    child.health = spec.health
    child.max_health = spec.max_health if spec.max_health is not None else spec.health
    child.move_speed = spec.move_speed
    child.reward_value = spec.reward_value
    child.size = spec.size
    child.contact_damage = spec.contact_damage
    apply_tint(child, spec.tint)
    if spec.orbit_angle is not None:
        child.orbit_angle = spec.orbit_angle
    if spec.orbit_radius is not None:
        child.orbit_radius = spec.orbit_radius


def randf(rng: Crand, mod: int, scale: float, base: float) -> float:
    return float(rng.rand() % mod) * scale + base


def apply_size_health_reward(
    c: CreatureInit,
    size: float,
    *,
    health_scale: float,
    health_add: float,
    reward_add: float = 50.0,
) -> None:
    c.size = size
    c.health = size * health_scale + health_add
    c.reward_value = size + size + reward_add


def apply_size_health(c: CreatureInit, size: float, *, health_scale: float, health_add: float) -> None:
    c.size = size
    c.health = size * health_scale + health_add


def apply_random_move_speed(c: CreatureInit, rng: Crand, mod: int, scale: float, base: float) -> None:
    c.move_speed = randf(rng, mod, scale, base)


def apply_size_move_speed(c: CreatureInit, size: float, scale: float, base: float) -> None:
    c.move_speed = size * scale + base


def spawn_ring_children(
    creatures: list[CreatureInit],
    template_id: int,
    pos_x: float,
    pos_y: float,
    rng: Crand,
    *,
    count: int,
    angle_step: float,
    radius: float,
    ai_mode: int,
    child_spec: FormationChildSpec,
    link_parent: int = 0,
    set_position: bool = False,
    heading_override: float | None = None,
) -> int:
    last_idx = -1
    for i in range(count):
        child = alloc_creature(template_id, pos_x, pos_y, rng)
        child.ai_mode = ai_mode
        child.ai_link_parent = link_parent
        angle = float(i) * angle_step
        child.target_offset_x = float(math.cos(angle) * radius)
        child.target_offset_y = float(math.sin(angle) * radius)
        if set_position:
            child.pos_x = pos_x + (child.target_offset_x or 0.0)
            child.pos_y = pos_y + (child.target_offset_y or 0.0)
        if heading_override is not None:
            child.heading = heading_override
        apply_child_spec(child, child_spec)
        creatures.append(child)
        last_idx = len(creatures) - 1
    return last_idx


def spawn_grid_children(
    creatures: list[CreatureInit],
    template_id: int,
    pos_x: float,
    pos_y: float,
    rng: Crand,
    *,
    x_range: range,
    y_range: range,
    ai_mode: int,
    child_spec: FormationChildSpec,
    link_parent: int = 0,
) -> int:
    last_idx = -1
    for x_offset in x_range:
        for y_offset in y_range:
            child = alloc_creature(template_id, pos_x, pos_y, rng)
            child.ai_mode = ai_mode
            child.ai_link_parent = link_parent
            child.target_offset_x = float(x_offset)
            child.target_offset_y = float(y_offset)
            child.pos_x = float(pos_x + x_offset)
            child.pos_y = float(pos_y + y_offset)
            apply_child_spec(child, child_spec)
            creatures.append(child)
            last_idx = len(creatures) - 1
    return last_idx


def spawn_chain_children(
    creatures: list[CreatureInit],
    template_id: int,
    pos_x: float,
    pos_y: float,
    rng: Crand,
    *,
    count: int,
    ai_mode: int,
    child_spec: FormationChildSpec,
    setup_child: Callable[[CreatureInit, int], None],
    link_parent_start: int = 0,
) -> int:
    chain_prev = link_parent_start
    for idx in range(count):
        child = alloc_creature(template_id, pos_x, pos_y, rng)
        child.ai_mode = ai_mode
        child.ai_link_parent = chain_prev
        setup_child(child, idx)
        apply_child_spec(child, child_spec)
        creatures.append(child)
        chain_prev = len(creatures) - 1
    return chain_prev


@dataclass(slots=True)
class PlanBuilder:
    template_id: int
    pos_x: float
    pos_y: float
    rng: Crand
    env: SpawnEnv
    creatures: list[CreatureInit]
    spawn_slots: list[SpawnSlotInit]
    effects: list[BurstEffect]
    primary: int = 0

    @classmethod
    def start(
        cls,
        template_id: int,
        pos: tuple[float, float],
        heading: float,
        rng: Crand,
        env: SpawnEnv,
    ) -> tuple["PlanBuilder", float]:
        pos_x, pos_y = pos

        # creature_alloc_slot() for the base creature.
        creatures: list[CreatureInit] = [alloc_creature(template_id, pos_x, pos_y, rng)]
        spawn_slots: list[SpawnSlotInit] = []
        effects: list[BurstEffect] = []

        # `heading == -100.0` uses a randomized heading.
        final_heading = heading
        if final_heading == -100.0:
            final_heading = float(rng.rand() % 628) * 0.01

        # Base initialization always consumes one rand() for a transient heading value.
        creatures[0].heading = float(rng.rand() % 314) * 0.01

        return cls(
            template_id=template_id,
            pos_x=pos_x,
            pos_y=pos_y,
            rng=rng,
            env=env,
            creatures=creatures,
            spawn_slots=spawn_slots,
            effects=effects,
            primary=0,
        ), final_heading

    @property
    def base(self) -> CreatureInit:
        return self.creatures[0]

    def add_slot(self, *, owner: int, timer: float, limit: int, interval: float, child: SupportsInt) -> int:
        return add_spawn_slot(
            self.spawn_slots,
            owner_creature=owner,
            timer=timer,
            limit=limit,
            interval=interval,
            child_template_id=int(child),
        )

    def ring_children(self, **kwargs) -> int:
        return spawn_ring_children(
            self.creatures,
            self.template_id,
            self.pos_x,
            self.pos_y,
            self.rng,
            **kwargs,
        )

    def grid_children(self, **kwargs) -> int:
        return spawn_grid_children(
            self.creatures,
            self.template_id,
            self.pos_x,
            self.pos_y,
            self.rng,
            **kwargs,
        )

    def chain_children(self, **kwargs) -> int:
        return spawn_chain_children(
            self.creatures,
            self.template_id,
            self.pos_x,
            self.pos_y,
            self.rng,
            **kwargs,
        )

    def finish(self, final_heading: float) -> SpawnPlan:
        apply_tail(
            template_id=self.template_id,
            plan_creatures=self.creatures,
            plan_spawn_slots=self.spawn_slots,
            plan_effects=self.effects,
            primary_idx=self.primary,
            final_heading=final_heading,
            env=self.env,
        )
        return SpawnPlan(
            creatures=tuple(self.creatures),
            spawn_slots=tuple(self.spawn_slots),
            effects=tuple(self.effects),
            primary=self.primary,
        )


TemplateFn = Callable[[PlanBuilder], None]
TEMPLATE_BUILDERS: dict[int, TemplateFn] = {}


def register_template(*template_ids: SupportsInt) -> Callable[[TemplateFn], TemplateFn]:
    def decorator(fn: TemplateFn) -> TemplateFn:
        for template_id in template_ids:
            TEMPLATE_BUILDERS[int(template_id)] = fn
        return fn

    return decorator


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


def alloc_creature(template_id: int, pos_x: float, pos_y: float, rng: Crand) -> CreatureInit:
    # creature_alloc_slot():
    # - clears flags
    # - seeds phase_seed = float(crt_rand() & 0x17f)
    phase_seed = float(rng.rand() & 0x17F)
    return CreatureInit(origin_template_id=template_id, pos_x=pos_x, pos_y=pos_y, heading=0.0, phase_seed=phase_seed)


def clamp01(value: float) -> float:
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

    c = alloc_creature(-1, pos_x, pos_y, rng)
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

    # size = rand() % 20 + 44
    c.size = float(rng.rand() % 20 + 44)

    # heading = (rand() % 314) * 0.01
    c.heading = float(rng.rand() % 314) * 0.01

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

    # Tint based on player_experience thresholds.
    tint_a = 1.0
    if xp < 50_000:
        tint_r = 1.0 - 1.0 / (float(xp // 1000) + 10.0)
        tint_g = float(rng.rand() % 10) * 0.01 + 0.9 - 1.0 / (float(xp // 10000) + 10.0)
        tint_b = float(rng.rand() % 10) * 0.01 + 0.7
    elif xp < 100_000:
        tint_r = 0.9 - 1.0 / (float(xp // 1000) + 10.0)
        tint_g = float(rng.rand() % 10) * 0.01 + 0.8 - 1.0 / (float(xp // 10000) + 10.0)
        tint_b = float(xp - 50_000) * 6e-06 + float(rng.rand() % 10) * 0.01 + 0.7
    else:
        tint_r = 1.0 - 1.0 / (float(xp // 1000) + 10.0)
        tint_g = float(rng.rand() % 10) * 0.01 + 0.9 - 1.0 / (float(xp // 10000) + 10.0)
        tint_b = float(rng.rand() % 10) * 0.01 + 1.0 - float(xp - 100_000) * 3e-06
        if tint_b < 0.5:
            tint_b = 0.5

    c.tint = (tint_r, tint_g, tint_b, tint_a)

    # contact_damage = size * 0.0952381
    c.contact_damage = float(c.size or 0.0) * (2.0 / 21.0)

    # reward_value is always 0.0 at this point in the original.
    c.reward_value = float(c.health or 0.0) * 0.4 + float(c.contact_damage or 0.0) * 0.8 + move_speed * 5.0 + float(rng.rand() % 10 + 10)

    # Rare stat overrides (color-coded variants).
    r = rng.rand()
    if r % 180 < 2:
        apply_tint(c, (0.9, 0.4, 0.4, 1.0))
        c.health = 65.0
        c.reward_value = 320.0
    else:
        r = rng.rand()
        if r % 240 < 2:
            apply_tint(c, (0.4, 0.9, 0.4, 1.0))
            c.health = 85.0
            c.reward_value = 420.0
        else:
            r = rng.rand()
            if r % 360 < 2:
                apply_tint(c, (0.4, 0.4, 0.9, 1.0))
                c.health = 125.0
                c.reward_value = 520.0

    # Rare health/size boosts (do not recompute contact_damage).
    r = rng.rand()
    if r % 1320 < 4:
        apply_tint(c, (0.84, 0.24, 0.89, 1.0))
        c.size = 80.0
        c.reward_value = 600.0
        c.health = float(c.health or 0.0) + 230.0
    else:
        r = rng.rand()
        if r % 1620 < 4:
            apply_tint(c, (0.94, 0.84, 0.29, 1.0))
            c.size = 85.0
            c.reward_value = 900.0
            c.health = float(c.health or 0.0) + 2230.0

    if c.health is not None:
        c.max_health = c.health
    if c.reward_value is not None:
        c.reward_value *= 0.8

    if c.tint is not None:
        tint_r, tint_g, tint_b, tint_a = c.tint
        c.tint = (
            clamp01(tint_r) if tint_r is not None else None,
            clamp01(tint_g) if tint_g is not None else None,
            clamp01(tint_b) if tint_b is not None else None,
            clamp01(tint_a) if tint_a is not None else None,
        )

    return c


def rand_survival_spawn_pos(rng: Crand, *, terrain_width: int, terrain_height: int) -> tuple[float, float]:
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
        interval_ms = 500 - int(survival_elapsed_ms) / 1800
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

    interval_ms = 500 - int(survival_elapsed_ms) // 1800

    spawns: list[CreatureInit] = []
    if interval_ms < 0:
        extra = (1 - interval_ms) >> 1
        interval_ms += int(extra) * 2
        for _ in range(int(extra)):
            pos = rand_survival_spawn_pos(rng, terrain_width=terrain_width, terrain_height=terrain_height)
            spawns.append(build_survival_spawn_creature(pos, rng, player_experience=player_experience))

    if interval_ms < 1:
        interval_ms = 1
    spawn_cooldown += float(interval_ms)

    pos = rand_survival_spawn_pos(rng, terrain_width=terrain_width, terrain_height=terrain_height)
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
            spawns.append(SpawnTemplateCall(template_id=SpawnId.FORMATION_RING_ALIEN_8_12, pos=(-164.0, 512.0), heading=heading))
            spawns.append(SpawnTemplateCall(template_id=SpawnId.FORMATION_RING_ALIEN_8_12, pos=(1188.0, 512.0), heading=heading))
            continue

        if stage == 1:
            if level < 9:
                break
            stage = 2
            spawns.append(SpawnTemplateCall(template_id=SpawnId.ALIEN_CONST_RED_BOSS_2C, pos=(1088.0, 512.0), heading=heading))
            continue

        if stage == 2:
            if level < 11:
                break
            stage = 3
            step = 128.0 / 3.0
            for i in range(12):
                spawns.append(SpawnTemplateCall(template_id=SpawnId.SPIDER_SP2_RANDOM_35, pos=(1088.0, float(i) * step + 256.0), heading=heading))
            continue

        if stage == 3:
            if level < 13:
                break
            stage = 4
            for i in range(4):
                spawns.append(SpawnTemplateCall(template_id=SpawnId.ALIEN_CONST_RED_FAST_2B, pos=(1088.0, float(i) * 64.0 + 384.0), heading=heading))
            continue

        if stage == 4:
            if level < 15:
                break
            stage = 5
            for i in range(4):
                spawns.append(SpawnTemplateCall(template_id=SpawnId.SPIDER_SP1_AI7_TIMER_38, pos=(1088.0, float(i) * 64.0 + 384.0), heading=heading))
            for i in range(4):
                spawns.append(SpawnTemplateCall(template_id=SpawnId.SPIDER_SP1_AI7_TIMER_38, pos=(-64.0, float(i) * 64.0 + 384.0), heading=heading))
            continue

        if stage == 5:
            if level < 17:
                break
            stage = 6
            spawns.append(SpawnTemplateCall(template_id=SpawnId.SPIDER_SP1_CONST_SHOCK_BOSS_3A, pos=(1088.0, 512.0), heading=heading))
            continue

        if stage == 6:
            if level < 19:
                break
            stage = 7
            spawns.append(SpawnTemplateCall(template_id=SpawnId.SPIDER_SP2_SPLITTER_01, pos=(640.0, 512.0), heading=heading))
            continue

        if stage == 7:
            if level < 21:
                break
            stage = 8
            spawns.append(SpawnTemplateCall(template_id=SpawnId.SPIDER_SP2_SPLITTER_01, pos=(384.0, 256.0), heading=heading))
            spawns.append(SpawnTemplateCall(template_id=SpawnId.SPIDER_SP2_SPLITTER_01, pos=(640.0, 768.0), heading=heading))
            continue

        if stage == 8:
            if level < 26:
                break
            stage = 9
            for i in range(4):
                spawns.append(SpawnTemplateCall(template_id=SpawnId.SPIDER_SP1_CONST_RANGED_VARIANT_3C, pos=(1088.0, float(i) * 64.0 + 384.0), heading=heading))
            for i in range(4):
                spawns.append(SpawnTemplateCall(template_id=SpawnId.SPIDER_SP1_CONST_RANGED_VARIANT_3C, pos=(-64.0, float(i) * 64.0 + 384.0), heading=heading))
            continue

        if stage == 9:
            if level <= 31:
                break
            stage = 10
            spawns.append(SpawnTemplateCall(template_id=SpawnId.SPIDER_SP1_CONST_SHOCK_BOSS_3A, pos=(1088.0, 512.0), heading=heading))
            spawns.append(SpawnTemplateCall(template_id=SpawnId.SPIDER_SP1_CONST_SHOCK_BOSS_3A, pos=(-64.0, 512.0), heading=heading))
            for i in range(4):
                spawns.append(SpawnTemplateCall(template_id=SpawnId.SPIDER_SP1_CONST_RANGED_VARIANT_3C, pos=(float(i) * 64.0 + 384.0, -64.0), heading=heading))
            for i in range(4):
                spawns.append(
                    SpawnTemplateCall(template_id=SpawnId.SPIDER_SP1_CONST_RANGED_VARIANT_3C, pos=(float(i) * 64.0 + 384.0, 1088.0), heading=heading)
                )
            continue

        break

    return stage, tuple(spawns)


def build_rush_mode_spawn_creature(
    pos: tuple[float, float],
    tint_rgba: TintRGBA,
    rng: Crand,
    *,
    type_id: int,
    survival_elapsed_ms: int,
) -> CreatureInit:
    """Pure model of `creature_spawn` (0x00428240) as used by `rush_mode_update` (0x004072b0)."""
    pos_x, pos_y = pos
    elapsed_ms = int(survival_elapsed_ms)

    c = alloc_creature(-1, pos_x, pos_y, rng)
    c.type_id = CreatureTypeId(type_id)
    c.ai_mode = 0

    c.health = float(elapsed_ms) * 1e-4 + 10.0
    c.heading = float(rng.rand() % 314) * 0.01
    c.move_speed = float(elapsed_ms) * 1e-5 + 2.5
    c.reward_value = float(rng.rand() % 30 + 140)

    c.tint = tint_rgba
    c.contact_damage = 4.0

    if c.health is not None:
        c.max_health = c.health
    c.size = float(elapsed_ms) * 1e-5 + 47.0

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
        tint_r = clamp01(t * (1.0 / 120000.0) + 0.3)
        tint_g = clamp01(t * 10000.0 + 0.3)
        tint_b = clamp01(math.sin(t * 1e-4) + 0.3)
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
        SpawnTemplateCall(template_id=SpawnId.ALIEN_CONST_GREEN_24, pos=(-164.0, 412.0), heading=heading),
        SpawnTemplateCall(template_id=SpawnId.ALIEN_CONST_PALE_GREEN_26, pos=(-184.0, 512.0), heading=heading),
        SpawnTemplateCall(template_id=SpawnId.ALIEN_CONST_GREEN_24, pos=(-154.0, 612.0), heading=heading),
    )


def build_tutorial_stage4_clear_spawns() -> tuple[SpawnTemplateCall, ...]:
    """Spawn pack triggered by the stage-4 "all clear" transition in `tutorial_timeline_update` (0x00408990)."""
    heading = float(math.pi)
    return (
        SpawnTemplateCall(template_id=SpawnId.ALIEN_CONST_GREEN_24, pos=(1188.0, 412.0), heading=heading),
        SpawnTemplateCall(template_id=SpawnId.ALIEN_CONST_PALE_GREEN_26, pos=(1208.0, 512.0), heading=heading),
        SpawnTemplateCall(template_id=SpawnId.ALIEN_CONST_GREEN_24, pos=(1178.0, 612.0), heading=heading),
    )


def build_tutorial_stage5_repeat_spawns(repeat_spawn_count: int) -> tuple[SpawnTemplateCall, ...]:
    """Spawn packs triggered by the stage-5 repeat loop in `tutorial_timeline_update` (0x00408990).

    `repeat_spawn_count` is the incremented counter value (1..7). When it reaches 8, the tutorial
    transitions instead of spawning more creatures.

    Note: the original also stores the returned creature pointer from template `0x27` in
    `tutorial_hint_bonus_ptr` and rewrites its packed bonus args (`link_index` low/high 16-bit fields)
    depending on `repeat_spawn_count`. This helper only reproduces the `creature_spawn_template` calls.
    """
    n = int(repeat_spawn_count)
    if n < 1 or 8 <= n:
        return ()

    heading = float(math.pi)
    spawns: list[SpawnTemplateCall] = []

    if (n & 1) == 0:
        # Even: right-side spawn pack (with an off-screen bottom-right spawn).
        if n < 6:
            spawns.append(SpawnTemplateCall(template_id=SpawnId.ALIEN_CONST_WEAPON_BONUS_27, pos=(1056.0, 1056.0), heading=heading))
        spawns.append(SpawnTemplateCall(template_id=SpawnId.ALIEN_CONST_GREEN_24, pos=(1188.0, 1136.0), heading=heading))
        spawns.append(SpawnTemplateCall(template_id=SpawnId.ALIEN_CONST_PALE_GREEN_26, pos=(1208.0, 512.0), heading=heading))
        spawns.append(SpawnTemplateCall(template_id=SpawnId.ALIEN_CONST_GREEN_24, pos=(1178.0, 612.0), heading=heading))
        if n == 4:
            spawns.append(SpawnTemplateCall(template_id=SpawnId.SPIDER_SP1_CONST_BLUE_40, pos=(512.0, 1056.0), heading=heading))
        return tuple(spawns)

    # Odd: left-side spawn pack.
    if n < 6:
        spawns.append(SpawnTemplateCall(template_id=SpawnId.ALIEN_CONST_WEAPON_BONUS_27, pos=(-32.0, 1056.0), heading=heading))
    spawns.extend(build_tutorial_stage3_fire_spawns())
    return tuple(spawns)


def build_tutorial_stage6_perks_done_spawns() -> tuple[SpawnTemplateCall, ...]:
    """Spawn pack triggered by the stage-6 "no perks pending" transition in `tutorial_timeline_update` (0x00408990)."""
    heading = float(math.pi)
    return (
        *build_tutorial_stage3_fire_spawns(),
        SpawnTemplateCall(template_id=SpawnId.ALIEN_CONST_PURPLE_28, pos=(-32.0, -32.0), heading=heading),
        *build_tutorial_stage4_clear_spawns(),
    )


def apply_tail(
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
        and not (c.flags & (CreatureFlags.RANGED_ATTACK_SHOCK | CreatureFlags.AI7_LINK_TIMER))
    ):
        c.flags |= CreatureFlags.AI7_LINK_TIMER
        c.ai_link_parent = None
        c.spawn_slot = None
        c.ai_timer = 0
        if c.move_speed is not None:
            c.move_speed *= 1.2

    # Hardcore tweak for template 0x38 only.
    if template_id == SpawnId.SPIDER_SP1_AI7_TIMER_38 and env.hardcore and c.move_speed is not None:
        c.move_speed *= 0.7

    c.heading = final_heading

    # Difficulty modifiers.
    has_spawn_slot = c.spawn_slot is not None and 0 <= c.spawn_slot < len(plan_spawn_slots)

    if not env.hardcore:
        # This is written as a short-circuit expression in the original:
        # for flag 0x4 creatures, always bump their spawn-slot interval by +0.2 in non-hardcore.
        if (c.flags & CreatureFlags.HAS_SPAWN_SLOT) and has_spawn_slot:
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

            if has_spawn_slot and (c.flags & CreatureFlags.HAS_SPAWN_SLOT):
                plan_spawn_slots[c.spawn_slot].interval += min(3.0, float(d) * 0.35)
    else:
        # In hardcore: difficulty level is forcibly cleared (global), and creature stats are buffed.
        if c.move_speed is not None:
            c.move_speed *= 1.05
        if c.contact_damage is not None:
            c.contact_damage *= 1.4
        if c.health is not None:
            c.health *= 1.2

        if has_spawn_slot and (c.flags & CreatureFlags.HAS_SPAWN_SLOT):
            plan_spawn_slots[c.spawn_slot].interval = max(
                0.1,
                plan_spawn_slots[c.spawn_slot].interval - 0.2,
            )


def apply_unhandled_creature_type_fallback(plan_creatures: list[CreatureInit], primary_idx: int) -> None:
    # Some template paths jump to the "Unhandled creatureType.\n" debug block in the original,
    # which forcibly overwrites `type_id` and `health` on the *current* creature pointer.
    # See artifacts/creature_spawn_template/binja-hlil.txt (label_431099).
    # Notably: templates 0x11..0x17 and 0x19 (see also artifacts/creature_spawn_template/ghidra.c LAB_00431094).
    c = plan_creatures[primary_idx]
    c.type_id = CreatureTypeId.ALIEN
    c.health = 20.0


def apply_alien_spawner(ctx: PlanBuilder, spec: AlienSpawnerSpec) -> None:
    c = ctx.base
    c.type_id = CreatureTypeId.ALIEN
    c.flags = CreatureFlags.ANIM_PING_PONG
    c.spawn_slot = ctx.add_slot(
        owner=0,
        timer=spec.timer,
        limit=spec.limit,
        interval=spec.interval,
        child=spec.child_template_id,
    )
    c.size = spec.size
    c.health = spec.health
    c.move_speed = spec.move_speed
    c.reward_value = spec.reward_value
    apply_tint(c, spec.tint)
    c.contact_damage = 0.0


def apply_constant_spawn(ctx: PlanBuilder, spec: ConstantSpawnSpec) -> None:
    c = ctx.base
    apply_constant_template(c, spec)


def apply_grid_formation(ctx: PlanBuilder, spec: GridFormationSpec) -> None:
    parent = ctx.base
    apply_constant_template(parent, spec.parent)
    if spec.set_parent_max_health and parent.health is not None:
        parent.max_health = parent.health
    ctx.primary = ctx.grid_children(
        x_range=spec.x_range,
        y_range=spec.y_range,
        ai_mode=spec.child_ai_mode,
        child_spec=spec.child_spec,
    )
    if spec.apply_fallback:
        apply_unhandled_creature_type_fallback(ctx.creatures, ctx.primary)


def apply_ring_formation(ctx: PlanBuilder, spec: RingFormationSpec) -> None:
    parent = ctx.base
    apply_constant_template(parent, spec.parent)
    if spec.set_parent_max_health and parent.health is not None:
        parent.max_health = parent.health
    ctx.primary = ctx.ring_children(
        count=spec.count,
        angle_step=spec.angle_step,
        radius=spec.radius,
        ai_mode=spec.child_ai_mode,
        child_spec=spec.child_spec,
        set_position=spec.set_position,
    )
    if spec.apply_fallback:
        apply_unhandled_creature_type_fallback(ctx.creatures, ctx.primary)


@register_template(SpawnId.ZOMBIE_BOSS_SPAWNER_00)
def template_00_zombie_boss_spawner(ctx: PlanBuilder) -> None:
    c = ctx.base
    c.type_id = CreatureTypeId.ZOMBIE
    c.flags = CreatureFlags.ANIM_PING_PONG | CreatureFlags.ANIM_LONG_STRIP
    c.spawn_slot = ctx.add_slot(
        owner=0,
        timer=1.0,
        limit=812,
        interval=0.7,
        child=SpawnId.ZOMBIE_RANDOM_41,
    )
    c.size = 64.0
    c.health = 8500.0
    c.move_speed = 1.3
    c.reward_value = 6600.0
    apply_tint(c, (0.6, 0.6, 1.0, 0.8))
    c.contact_damage = 50.0


BASIC_RANDOM_TYPE_IDS: dict[int, CreatureTypeId] = {
    SpawnId.SPIDER_SP1_RANDOM_03: CreatureTypeId.SPIDER_SP1,
    SpawnId.SPIDER_SP2_RANDOM_05: CreatureTypeId.SPIDER_SP2,
    SpawnId.ALIEN_RANDOM_06: CreatureTypeId.ALIEN,
}


@register_template(SpawnId.SPIDER_SP1_RANDOM_03, SpawnId.SPIDER_SP2_RANDOM_05, SpawnId.ALIEN_RANDOM_06)
def template_03_05_06_basic_random(ctx: PlanBuilder) -> None:
    c = ctx.base
    c.type_id = BASIC_RANDOM_TYPE_IDS[ctx.template_id]
    size = randf(ctx.rng, 15, 1.0, 38.0)
    apply_size_health_reward(c, size, health_scale=8.0 / 7.0, health_add=20.0)
    apply_random_move_speed(c, ctx.rng, 18, 0.1, 1.1)
    tint_b = randf(ctx.rng, 25, 0.01, 0.8)
    apply_tint(c, (0.6, 0.6, clamp01(tint_b), 1.0))
    c.contact_damage = randf(ctx.rng, 10, 1.0, 4.0)


@register_template(SpawnId.LIZARD_RANDOM_04)
def template_04_lizard_random(ctx: PlanBuilder) -> None:
    c = ctx.base
    c.type_id = CreatureTypeId.LIZARD
    size = randf(ctx.rng, 15, 1.0, 38.0)
    apply_size_health_reward(c, size, health_scale=8.0 / 7.0, health_add=20.0)
    apply_tint(c, (0.67, 0.67, 1.0, 1.0))
    apply_random_move_speed(c, ctx.rng, 18, 0.1, 1.1)
    c.contact_damage = randf(ctx.rng, 10, 1.0, 4.0)


@register_template(SpawnId.ALIEN_SPAWNER_RING_24_0E)
def template_0e_alien_spawner_ring_24(ctx: PlanBuilder) -> None:
    parent = ctx.base
    parent.type_id = CreatureTypeId.ALIEN
    parent.flags = CreatureFlags.ANIM_PING_PONG
    parent.spawn_slot = ctx.add_slot(
        owner=0,
        timer=1.5,
        limit=64,
        interval=1.05,
        child=SpawnId.AI1_LIZARD_BLUE_TINT_1C,
    )
    parent.size = 32.0
    parent.health = 50.0
    parent.move_speed = 2.8
    parent.reward_value = 5000.0
    apply_tint(parent, (0.9, 0.8, 0.4, 1.0))
    parent.contact_damage = 0.0

    child_spec = FormationChildSpec(
        type_id=CreatureTypeId.ALIEN,
        health=40.0,
        move_speed=4.0,
        reward_value=350.0,
        size=35.0,
        contact_damage=30.0,
        tint=(1.0, 0.3, 0.3, 1.0),
    )
    ctx.primary = ctx.ring_children(
        count=24,
        angle_step=math.pi / 12.0,
        radius=100.0,
        ai_mode=3,
        child_spec=child_spec,
        heading_override=0.0,
    )


@register_template(SpawnId.FORMATION_CHAIN_LIZARD_4_11)
def template_11_formation_chain_lizard_4(ctx: PlanBuilder) -> None:
    parent = ctx.base
    parent.type_id = CreatureTypeId.LIZARD
    parent.ai_mode = 1
    apply_tint(parent, (0.99, 0.99, 0.21, 1.0))
    parent.health = 1500.0
    parent.max_health = 1500.0
    parent.move_speed = 2.1
    parent.reward_value = 1000.0
    parent.size = 69.0
    parent.contact_damage = 150.0

    # Spawns a linked chain of 4 children (link points to previous). The original also sets
    # the base creature's link_index to the last child after the loop.
    child_spec = FormationChildSpec(
        type_id=CreatureTypeId.LIZARD,
        health=60.0,
        move_speed=2.4,
        reward_value=60.0,
        size=50.0,
        contact_damage=14.0,
        tint=(0.6, 0.6, 0.31, 1.0),
    )
    pos_x = ctx.pos_x
    pos_y = ctx.pos_y

    def setup_child(child: CreatureInit, idx: int) -> None:
        child.target_offset_x = -256.0 + float(idx) * 64.0
        child.target_offset_y = -256.0
        angle = float(2 + idx * 2) * (math.pi / 8.0)
        child.pos_x = float(math.cos(angle) * 256.0 + pos_x)
        child.pos_y = float(math.sin(angle) * 256.0 + pos_y)

    chain_prev = ctx.chain_children(
        count=4,
        ai_mode=3,
        child_spec=child_spec,
        setup_child=setup_child,
    )

    parent.ai_link_parent = chain_prev
    ctx.primary = chain_prev
    apply_unhandled_creature_type_fallback(ctx.creatures, ctx.primary)


@register_template(SpawnId.FORMATION_CHAIN_ALIEN_10_13)
def template_13_formation_chain_alien_10(ctx: PlanBuilder) -> None:
    parent = ctx.base
    parent.type_id = CreatureTypeId.ALIEN
    parent.ai_mode = 6
    parent.pos_x = ctx.pos_x + 256.0
    parent.pos_y = ctx.pos_y
    apply_tint(parent, (0.6, 0.8, 0.91, 1.0))
    parent.health = 200.0
    parent.max_health = 200.0
    parent.move_speed = 2.0
    parent.reward_value = 600.0
    parent.size = 40.0
    parent.contact_damage = 20.0

    child_spec = FormationChildSpec(
        type_id=CreatureTypeId.ALIEN,
        health=60.0,
        move_speed=2.0,
        reward_value=60.0,
        size=50.0,
        contact_damage=4.0,
        tint=(0.4, 0.7, 0.11, 1.0),
        orbit_angle=math.pi,
        orbit_radius=10.0,
    )
    pos_x = ctx.pos_x
    pos_y = ctx.pos_y

    def setup_child(child: CreatureInit, idx: int) -> None:
        angle_idx = 2 + idx * 2
        angle = float(angle_idx) * math.radians(20.0)
        child.pos_x = float(math.cos(angle) * 256.0 + pos_x)
        child.pos_y = float(math.sin(angle) * 256.0 + pos_y)

    chain_prev = ctx.chain_children(
        count=10,
        ai_mode=6,
        child_spec=child_spec,
        setup_child=setup_child,
    )

    parent.ai_link_parent = chain_prev
    ctx.primary = chain_prev
    apply_unhandled_creature_type_fallback(ctx.creatures, ctx.primary)


AI1_BLUE_TINT_TEMPLATES: dict[int, tuple[CreatureTypeId, float]] = {
    SpawnId.AI1_ALIEN_BLUE_TINT_1A: (CreatureTypeId.ALIEN, 50.0),
    SpawnId.AI1_SPIDER_SP1_BLUE_TINT_1B: (CreatureTypeId.SPIDER_SP1, 40.0),
    SpawnId.AI1_LIZARD_BLUE_TINT_1C: (CreatureTypeId.LIZARD, 50.0),
}


@register_template(SpawnId.AI1_ALIEN_BLUE_TINT_1A, SpawnId.AI1_SPIDER_SP1_BLUE_TINT_1B, SpawnId.AI1_LIZARD_BLUE_TINT_1C)
def template_1a_1b_1c_ai1_blue_tint(ctx: PlanBuilder) -> None:
    c = ctx.base
    c.ai_mode = 1
    c.size = 50.0
    c.move_speed = 2.4
    c.reward_value = 125.0

    c.type_id, c.health = AI1_BLUE_TINT_TEMPLATES[ctx.template_id]

    tint = float(ctx.rng.rand() % 40) * 0.01 + 0.5
    apply_tint(c, (tint, tint, 1.0, 1.0))
    c.contact_damage = 5.0


@register_template(SpawnId.ALIEN_RANDOM_1D)
def template_1d_alien_random(ctx: PlanBuilder) -> None:
    c = ctx.base
    c.type_id = CreatureTypeId.ALIEN
    size = randf(ctx.rng, 20, 1.0, 35.0)
    apply_size_health(c, size, health_scale=8.0 / 7.0, health_add=10.0)
    apply_random_move_speed(c, ctx.rng, 15, 0.1, 1.1)
    c.reward_value = randf(ctx.rng, 100, 1.0, 50.0)
    apply_tint(
        c,
        (
            randf(ctx.rng, 50, 0.001, 0.6),
            randf(ctx.rng, 50, 0.01, 0.5),
            randf(ctx.rng, 50, 0.001, 0.6),
            1.0,
        ),
    )
    c.contact_damage = randf(ctx.rng, 10, 1.0, 4.0)


@register_template(SpawnId.ALIEN_RANDOM_1E)
def template_1e_alien_random(ctx: PlanBuilder) -> None:
    c = ctx.base
    c.type_id = CreatureTypeId.ALIEN
    size = randf(ctx.rng, 30, 1.0, 35.0)
    apply_size_health(c, size, health_scale=16.0 / 7.0, health_add=10.0)
    apply_random_move_speed(c, ctx.rng, 17, 0.1, 1.5)
    c.reward_value = randf(ctx.rng, 200, 1.0, 50.0)
    apply_tint(
        c,
        (
            randf(ctx.rng, 50, 0.001, 0.6),
            randf(ctx.rng, 50, 0.001, 0.6),
            randf(ctx.rng, 50, 0.01, 0.5),
            1.0,
        ),
    )
    c.contact_damage = randf(ctx.rng, 30, 1.0, 4.0)


@register_template(SpawnId.ALIEN_RANDOM_1F)
def template_1f_alien_random(ctx: PlanBuilder) -> None:
    c = ctx.base
    c.type_id = CreatureTypeId.ALIEN
    size = randf(ctx.rng, 30, 1.0, 45.0)
    apply_size_health(c, size, health_scale=26.0 / 7.0, health_add=30.0)
    apply_random_move_speed(c, ctx.rng, 21, 0.1, 1.6)
    c.reward_value = randf(ctx.rng, 200, 1.0, 80.0)
    apply_tint(
        c,
        (
            randf(ctx.rng, 50, 0.01, 0.5),
            randf(ctx.rng, 50, 0.001, 0.6),
            randf(ctx.rng, 50, 0.001, 0.6),
            1.0,
        ),
    )
    c.contact_damage = randf(ctx.rng, 35, 1.0, 8.0)


@register_template(SpawnId.ALIEN_RANDOM_GREEN_20)
def template_20_alien_random_green(ctx: PlanBuilder) -> None:
    c = ctx.base
    c.type_id = CreatureTypeId.ALIEN
    size = randf(ctx.rng, 30, 1.0, 40.0)
    apply_size_health_reward(c, size, health_scale=8.0 / 7.0, health_add=20.0)
    apply_random_move_speed(c, ctx.rng, 18, 0.1, 1.1)
    tint_g = randf(ctx.rng, 40, 0.01, 0.6)
    apply_tint(c, (0.3, tint_g, 0.3, 1.0))
    c.contact_damage = randf(ctx.rng, 10, 1.0, 4.0)


@register_template(SpawnId.LIZARD_RANDOM_2E)
def template_2e_lizard_random(ctx: PlanBuilder) -> None:
    c = ctx.base
    c.type_id = CreatureTypeId.LIZARD
    size = randf(ctx.rng, 30, 1.0, 40.0)
    apply_size_health_reward(c, size, health_scale=8.0 / 7.0, health_add=20.0)
    apply_random_move_speed(c, ctx.rng, 18, 0.1, 1.1)
    apply_tint(
        c,
        (
            randf(ctx.rng, 40, 0.01, 0.6),
            randf(ctx.rng, 40, 0.01, 0.6),
            randf(ctx.rng, 40, 0.01, 0.6),
            1.0,
        ),
    )
    c.contact_damage = randf(ctx.rng, 10, 1.0, 4.0)


@register_template(SpawnId.LIZARD_RANDOM_31)
def template_31_lizard_random(ctx: PlanBuilder) -> None:
    c = ctx.base
    c.type_id = CreatureTypeId.LIZARD
    size = randf(ctx.rng, 30, 1.0, 40.0)
    apply_size_health_reward(c, size, health_scale=8.0 / 7.0, health_add=10.0)
    apply_random_move_speed(c, ctx.rng, 18, 0.1, 1.1)
    tint = randf(ctx.rng, 30, 0.01, 0.6)
    apply_tint(c, (tint, tint, 0.38, 1.0))
    c.contact_damage = size * 0.14 + 4.0


@register_template(SpawnId.SPIDER_SP1_RANDOM_32)
def template_32_spider_sp1_random(ctx: PlanBuilder) -> None:
    c = ctx.base
    c.type_id = CreatureTypeId.SPIDER_SP1
    size = randf(ctx.rng, 25, 1.0, 40.0)
    apply_size_health_reward(c, size, health_scale=1.0, health_add=10.0)
    apply_random_move_speed(c, ctx.rng, 17, 0.1, 1.1)
    tint = randf(ctx.rng, 40, 0.01, 0.6)
    apply_tint(c, (tint, tint, tint, 1.0))
    c.contact_damage = size * 0.14 + 4.0


@register_template(SpawnId.SPIDER_SP1_RANDOM_RED_33)
def template_33_spider_sp1_random_red(ctx: PlanBuilder) -> None:
    c = ctx.base
    c.type_id = CreatureTypeId.SPIDER_SP1
    size = randf(ctx.rng, 15, 1.0, 45.0)
    apply_size_health_reward(c, size, health_scale=8.0 / 7.0, health_add=20.0)
    apply_random_move_speed(c, ctx.rng, 18, 0.1, 1.1)
    apply_tint(c, (randf(ctx.rng, 40, 0.01, 0.6), 0.5, 0.5, 1.0))
    c.contact_damage = randf(ctx.rng, 10, 1.0, 4.0)


@register_template(SpawnId.SPIDER_SP1_RANDOM_GREEN_34)
def template_34_spider_sp1_random_green(ctx: PlanBuilder) -> None:
    c = ctx.base
    c.type_id = CreatureTypeId.SPIDER_SP1
    size = randf(ctx.rng, 20, 1.0, 40.0)
    apply_size_health_reward(c, size, health_scale=8.0 / 7.0, health_add=20.0)
    apply_random_move_speed(c, ctx.rng, 18, 0.1, 1.1)
    apply_tint(c, (0.5, randf(ctx.rng, 40, 0.01, 0.6), 0.5, 1.0))
    c.contact_damage = randf(ctx.rng, 10, 1.0, 4.0)


@register_template(SpawnId.SPIDER_SP2_RANDOM_35)
def template_35_spider_sp2_random(ctx: PlanBuilder) -> None:
    c = ctx.base
    c.type_id = CreatureTypeId.SPIDER_SP2
    size = randf(ctx.rng, 10, 1.0, 30.0)
    apply_size_health_reward(c, size, health_scale=8.0 / 7.0, health_add=20.0)
    apply_random_move_speed(c, ctx.rng, 18, 0.1, 1.1)
    apply_tint(c, (0.8, randf(ctx.rng, 20, 0.01, 0.8), 0.8, 1.0))
    c.contact_damage = randf(ctx.rng, 10, 1.0, 4.0)


@register_template(SpawnId.ALIEN_AI7_ORBITER_36)
def template_36_alien_ai7_orbiter(ctx: PlanBuilder) -> None:
    c = ctx.base
    c.type_id = CreatureTypeId.ALIEN
    c.size = 50.0
    c.ai_mode = 7
    c.orbit_radius = 1.5
    c.health = 10.0
    c.move_speed = 1.8
    c.reward_value = 150.0
    tint_g = float(ctx.rng.rand() % 5) * 0.01 + 0.65
    apply_tint(c, (0.65, tint_g, 0.95, 1.0))
    c.contact_damage = 40.0


@register_template(SpawnId.SPIDER_SP2_RANGED_VARIANT_37)
def template_37_spider_sp2_ranged_variant(ctx: PlanBuilder) -> None:
    c = ctx.base
    c.type_id = CreatureTypeId.SPIDER_SP2
    c.flags = CreatureFlags.RANGED_ATTACK_VARIANT
    c.health = 50.0
    c.move_speed = 3.2
    c.reward_value = 433.0
    apply_tint(c, (1.0, 0.75, 0.1, 1.0))
    c.size = float((ctx.rng.rand() & 3) + 41)
    c.contact_damage = 10.0


@register_template(SpawnId.SPIDER_SP1_AI7_TIMER_38)
def template_38_spider_sp1_ai7_timer(ctx: PlanBuilder) -> None:
    c = ctx.base
    c.type_id = CreatureTypeId.SPIDER_SP1
    c.flags = CreatureFlags.AI7_LINK_TIMER
    c.ai_timer = 0
    c.health = 50.0
    c.move_speed = 4.8
    c.reward_value = 433.0
    apply_tint(c, (1.0, 0.75, 0.1, 1.0))
    c.size = float((ctx.rng.rand() & 3) + 41)
    c.contact_damage = 10.0


@register_template(SpawnId.SPIDER_SP1_AI7_TIMER_WEAK_39)
def template_39_spider_sp1_ai7_timer_weak(ctx: PlanBuilder) -> None:
    c = ctx.base
    c.type_id = CreatureTypeId.SPIDER_SP1
    c.flags = CreatureFlags.AI7_LINK_TIMER
    c.ai_timer = 0
    c.health = 4.0
    c.move_speed = 4.8
    c.reward_value = 50.0
    apply_tint(c, (0.8, 0.65, 0.1, 1.0))
    c.size = float(ctx.rng.rand() % 4 + 26)
    c.contact_damage = 10.0


@register_template(SpawnId.SPIDER_SP1_RANDOM_3D)
def template_3d_spider_sp1_random(ctx: PlanBuilder) -> None:
    c = ctx.base
    c.type_id = CreatureTypeId.SPIDER_SP1
    c.health = 70.0
    c.move_speed = 2.6
    c.reward_value = 120.0
    tint = float(ctx.rng.rand() % 20) * 0.01 + 0.8
    apply_tint(c, (tint, tint, tint, 1.0))
    size = float(ctx.rng.rand() % 7 + 45)
    c.size = size
    c.contact_damage = size * 0.22


@register_template(SpawnId.ZOMBIE_RANDOM_41)
def template_41_zombie_random(ctx: PlanBuilder) -> None:
    c = ctx.base
    c.type_id = CreatureTypeId.ZOMBIE
    size = randf(ctx.rng, 30, 1.0, 40.0)
    apply_size_health_reward(c, size, health_scale=8.0 / 7.0, health_add=10.0)
    apply_size_move_speed(c, size, 0.0025, 0.9)
    tint = randf(ctx.rng, 40, 0.01, 0.6)
    apply_tint(c, (tint, tint, tint, 1.0))
    c.contact_damage = randf(ctx.rng, 10, 1.0, 4.0)


def build_spawn_plan(
    template_id: SupportsInt,
    pos: tuple[float, float],
    heading: float,
    rng: Crand,
    env: SpawnEnv,
) -> SpawnPlan:
    """Pure plan builder modeled after `creature_spawn_template` (0x00430AF0).

    The plan lists:
      - every creature allocated and configured directly by the template
      - any spawn-slot configurations (deferred child spawns)
      - side-effects like burst FX
    """
    template_id = int(template_id)
    ctx, final_heading = PlanBuilder.start(template_id, pos, heading, rng, env)

    if builder := TEMPLATE_BUILDERS.get(template_id):
        builder(ctx)
    elif spec := ALIEN_SPAWNER_TEMPLATES.get(template_id):
        apply_alien_spawner(ctx, spec)
    elif spec := GRID_FORMATIONS.get(template_id):
        apply_grid_formation(ctx, spec)
    elif spec := RING_FORMATIONS.get(template_id):
        apply_ring_formation(ctx, spec)
    elif spec := CONSTANT_SPAWN_TEMPLATES.get(template_id):
        apply_constant_spawn(ctx, spec)
    else:
        raise NotImplementedError(f"spawn plan not implemented for template_id=0x{template_id:x}")

    return ctx.finish(final_heading)
