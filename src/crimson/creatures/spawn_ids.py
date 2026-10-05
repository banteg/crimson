from __future__ import annotations

from enum import IntEnum, IntFlag

Tint = tuple[float | None, float | None, float | None, float | None]

# Heading sentinel that forces randomized heading in `creature_spawn_template`.
RANDOM_HEADING_SENTINEL = -100.0


class CreatureTypeId(IntEnum):
    ZOMBIE = 0
    LIZARD = 1
    ALIEN = 2
    SPIDER_SP1 = 3
    SPIDER_SP2 = 4
    TROOPER = 5


class CreatureAiMode(IntEnum):
    FLANK_PLAYER = 0
    FLANK_PLAYER_TIGHT = 1
    CHASE_PLAYER = 2
    FOLLOW_LINK = 3
    FLANK_PLAYER_LINKED = 4
    FOLLOW_LINK_TETHERED = 5
    ORBIT_LINK = 6
    HOLD_TIMER = 7
    FLANK_PLAYER_WIDE = 8


class CreatureFlags(IntFlag):
    POISONED = 0x01  # Poison Bullets / Veins of Poison: self-damage dt * 60, red aura
    POISONED_STRONG = 0x02  # Toxic Avenger: self-damage dt * 180
    SPAWNER = 0x04  # nest: emits from its spawn slot (link_index), pinned in place; ping-pong strip
    SPLIT_ON_DEATH = 0x08  # split-on-death behavior
    RANGED_PLASMA_RIFLE = 0x10  # fires the Plasma Rifle projectile
    SPAWNER_MOBILE = 0x40  # a SPAWNER that keeps walking; long animation strip
    STOP_AND_GO = 0x80  # link_index counts ms: hold, then move, then hold again
    RANGED_TEMPLATE_PROJECTILE = 0x100  # fires the projectile type stored in orbit_radius
    BONUS_ON_DEATH = 0x400  # spawns bonus on death



# Semantic names are provenance-backed against the remake creature data; see
# docs/creatures/spawning.md. Numeric suffixes preserve the native Windows ids.
class SpawnId(IntEnum):
    ZOMBIE_BOSS_SPAWNER_00 = 0x00
    SPIDER_SP2_SPLITTER_01 = 0x01
    UNUSED_02 = 0x02
    SPIDER_SP1_RANDOM_03 = 0x03
    LIZARD_RANDOM_04 = 0x04
    SPIDER_SP2_RANDOM_05 = 0x05
    ALIEN_RANDOM_06 = 0x06

    DEN_ALIEN_BASIC_07 = 0x07
    DEN_ALIEN_BASIC_SLOWER_08 = 0x08
    DEN_ALIEN_WEAK_SMALL_09 = 0x09
    DEN_SPIDER_BASIC_0A = 0x0A
    DEN_SPIDER_PLASMA_SHOOTERS_0B = 0x0B
    DEN_LIZARD_WEAK_0C = 0x0C
    DEN_LIZARD_WEAK_SLOWER_0D = 0x0D
    ALIEN_SPAWNER_RING_24_0E = 0x0E
    ALIEN_GHOST_0F = 0x0F
    DEN_SPIDER_WEAK_10 = 0x10

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

    ALIEN_HIDDEN_1_21 = 0x21
    ALIEN_HIDDEN_2_22 = 0x22
    ALIEN_HIDDEN_3_23 = 0x23
    ALIEN_CONST_GREEN_24 = 0x24
    ALIEN_SMALL_GREEN_MAN_25 = 0x25
    ALIEN_SMALL_GRAY_26 = 0x26
    ALIEN_BONUS_CARRIER_27 = 0x27
    ALIEN_CONST_PURPLE_28 = 0x28
    ALIEN_BIG_GRAY_29 = 0x29
    ALIEN_CONST_GREY_FAST_2A = 0x2A
    ALIEN_DEADLY_FAST_2B = 0x2B
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

    ALIEN_DELAYED_START_36 = 0x36
    SPIDER_SP2_RANGED_VARIANT_37 = 0x37
    SPIDER_SP1_STOP_AND_GO_38 = 0x38
    SPIDER_SP1_STOP_AND_GO_WEAK_39 = 0x39

    SPIDER_BOSS_3A = 0x3A
    SPIDER_SP1_CONST_RED_BOSS_3B = 0x3B
    SPIDER_PLASMA_SHOOTER_3C = 0x3C
    SPIDER_SP1_RANDOM_3D = 0x3D
    SPIDER_SP1_CONST_WHITE_FAST_3E = 0x3E
    SPIDER_SP1_CONST_BROWN_SMALL_3F = 0x3F
    SPIDER_SMALL_BLUE_40 = 0x40

    ZOMBIE_RANDOM_41 = 0x41
    ZOMBIE_SMALL_WHITE_42 = 0x42
    ZOMBIE_CONST_GREEN_BRUTE_43 = 0x43
