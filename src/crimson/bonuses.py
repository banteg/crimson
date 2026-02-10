from __future__ import annotations

"""Bonus ids extracted from bonus_metadata_init (bonus_meta_label)."""

from dataclasses import dataclass
from enum import IntEnum


class BonusId(IntEnum):
    UNUSED = 0
    POINTS = 1
    ENERGIZER = 2
    WEAPON = 3
    WEAPON_POWER_UP = 4
    NUKE = 5
    DOUBLE_EXPERIENCE = 6
    SHOCK_CHAIN = 7
    FIREBLAST = 8
    REFLEX_BOOST = 9
    SHIELD = 10
    FREEZE = 11
    MEDIKIT = 12
    SPEED = 13
    FIRE_BULLETS = 14


@dataclass(frozen=True, slots=True)
class BonusMeta:
    bonus_id: BonusId
    name: str
    description: str | None
    icon_id: int | None
    default_amount: int | None
    apply_seconds: float | None = None
    notes: str | None = None


BONUS_TABLE = [
    BonusMeta(
        bonus_id=BonusId.UNUSED,
        name="(unused)",
        description=None,
        icon_id=None,
        default_amount=None,
        notes="`DAT_004853dc` is set to `0`, disabling this entry.",
    ),
    BonusMeta(
        bonus_id=BonusId.POINTS,
        name="Points",
        description="You gain some experience points.",
        icon_id=12,
        default_amount=500,
        notes="`bonus_apply` adds `default_amount` to score.",
    ),
    BonusMeta(
        bonus_id=BonusId.ENERGIZER,
        name="Energizer",
        description="Suddenly monsters run away from you and you can eat them.",
        icon_id=10,
        default_amount=8,
        apply_seconds=8.0,
        notes="`bonus_apply` updates `bonus_energizer_timer` (fixed +8 seconds, scaled by Bonus Economist).",
    ),
    BonusMeta(
        bonus_id=BonusId.WEAPON,
        name="Weapon",
        description="You get a new weapon.",
        icon_id=-1,
        default_amount=3,
        notes="`bonus_apply` treats `default_amount` as weapon id; often overridden.",
    ),
    BonusMeta(
        bonus_id=BonusId.WEAPON_POWER_UP,
        name="Weapon Power Up",
        description="Your firerate and load time increase for a short period.",
        icon_id=7,
        default_amount=10,
        notes="`bonus_apply` updates `bonus_weapon_power_up_timer`.",
    ),
    BonusMeta(
        bonus_id=BonusId.NUKE,
        name="Nuke",
        description="An amazing explosion of ATOMIC power.",
        icon_id=1,
        # Native bonus entries store amount=1 for Nuke spawns.
        # This participates in the original amount-vs-weapon-id suppression bug
        # when preserve_bugs mode is enabled.
        default_amount=1,
        notes="`bonus_apply` performs the large explosion + shake sequence.",
    ),
    BonusMeta(
        bonus_id=BonusId.DOUBLE_EXPERIENCE,
        name="Double Experience",
        description="Every experience point you get is doubled when this bonus is active.",
        icon_id=4,
        # Native default amount is 0; the pickup adds a fixed 6 seconds (scaled by Bonus Economist).
        default_amount=0,
        apply_seconds=6.0,
        notes="`bonus_apply` updates `bonus_double_xp_timer` (fixed +6 seconds, scaled by Bonus Economist).",
    ),
    BonusMeta(
        bonus_id=BonusId.SHOCK_CHAIN,
        name="Shock Chain",
        description="Chain of shocks shock the crowd.",
        icon_id=3,
        default_amount=0,
        notes="`bonus_apply` spawns chained lightning via `projectile_spawn` type `0x15`; `shock_chain_links_left` / `shock_chain_projectile_id` track the active chain.",
    ),
    BonusMeta(
        bonus_id=BonusId.FIREBLAST,
        name="Fireblast",
        description="Fireballs all over the place.",
        icon_id=2,
        default_amount=0,
        notes="`bonus_apply` spawns a radial projectile burst (type `9`).",
    ),
    BonusMeta(
        bonus_id=BonusId.REFLEX_BOOST,
        name="Reflex Boost",
        description="You get more time to react as the game slows down.",
        icon_id=5,
        default_amount=3,
        notes="`bonus_apply` updates `bonus_reflex_boost_timer`.",
    ),
    BonusMeta(
        bonus_id=BonusId.SHIELD,
        name="Shield",
        description="Force field protects you for a while.",
        icon_id=6,
        default_amount=7,
        notes="`bonus_apply` updates `player_shield_timer` (`DAT_00490bc8`).",
    ),
    BonusMeta(
        bonus_id=BonusId.FREEZE,
        name="Freeze",
        description="Monsters are frozen.",
        icon_id=8,
        default_amount=5,
        notes="`bonus_apply` updates `bonus_freeze_timer`.",
    ),
    BonusMeta(
        bonus_id=BonusId.MEDIKIT,
        name="MediKit",
        description="You regain some of your health.",
        icon_id=14,
        default_amount=10,
        notes="`bonus_apply` restores health in 10-point increments.",
    ),
    BonusMeta(
        bonus_id=BonusId.SPEED,
        name="Speed",
        description="Your movement speed increases for a while.",
        icon_id=9,
        default_amount=8,
        notes="`bonus_apply` updates `player_speed_bonus_timer` (`DAT_00490bc4`).",
    ),
    BonusMeta(
        bonus_id=BonusId.FIRE_BULLETS,
        name="Fire Bullets",
        description="For few seconds -- make them count.",
        icon_id=11,
        # Native default amount is 4; the pickup adds a fixed 5 seconds (scaled by Bonus Economist).
        default_amount=4,
        apply_seconds=5.0,
        notes="`bonus_apply` updates `player_fire_bullets_timer` (`DAT_00490bcc`) (fixed +5 seconds, scaled by Bonus Economist). While active, `projectile_spawn` overrides player-owned projectiles to type `0x2d` (pellet count from `weapon_projectile_pellet_count[weapon_id]`).",
    ),
]

BONUS_BY_ID = {int(entry.bonus_id): entry for entry in BONUS_TABLE}


def bonus_label(bonus_id: int) -> str:
    entry = BONUS_BY_ID.get(bonus_id)
    if entry is None:
        return "unknown"
    return entry.name
