from __future__ import annotations

from typing import TYPE_CHECKING

from ..game_modes import GameMode
from ..perks import PerkId
from ..perks.helpers import perk_active
from .ids import BONUS_BY_ID, BonusId

if TYPE_CHECKING:
    from grim.rand import CrandLike

    from ..gameplay import GameplayState
    from ..sim.state_types import PlayerState
    from .pool import BonusPool


def _bonus_enabled(bonus_id: BonusId) -> bool:
    meta = BONUS_BY_ID.get(bonus_id)
    if meta is None:
        return False
    return meta.bonus_id != BonusId.UNUSED


def _bonus_id_from_roll(roll: int, rng: CrandLike) -> BonusId:
    # Mirrors `bonus_pick_random_type` (0x412470) mapping:
    # - roll = rand() % 162 + 1  (1..162)
    # - Points: roll 1..13
    # - Energizer: roll 14 with (rand & 0x3F) == 0, else Weapon
    # - Bucketed ids 3..14 via a 10-step loop; if it would exceed 14, returns 0
    #   to force a reroll (matching the `goto LABEL_18` path leaving `v3 == 0`).
    if roll < 1 or roll > 162:
        return BonusId.UNUSED

    if roll <= 13:
        return BonusId.POINTS

    if roll == 14:
        if (rng.rand() & 0x3F) == 0:
            return BonusId.ENERGIZER
        return BonusId.WEAPON

    v5 = roll - 14
    v6 = int(BonusId.WEAPON)
    while v5 > 10:
        v5 -= 10
        v6 += 1
        if v6 >= 15:
            return BonusId.UNUSED
    return BonusId(v6)


def _bonus_pick_suppressed(
    *,
    state: GameplayState,
    players: list[PlayerState],
    bonus_id: BonusId,
    has_fire_bullets_drop: bool,
) -> bool:
    if not _bonus_enabled(bonus_id):
        return True
    if state.shock_chain_links_left > 0 and bonus_id == BonusId.SHOCK_CHAIN:
        return True
    if bonus_id == BonusId.FREEZE and state.bonuses.freeze > 0.0:
        return True
    if bonus_id == BonusId.SHIELD and any(player.shield_timer > 0.0 for player in players):
        return True
    if bonus_id == BonusId.WEAPON and has_fire_bullets_drop:
        return True
    if bonus_id == BonusId.WEAPON and any(perk_active(player, PerkId.MY_FAVOURITE_WEAPON) for player in players):
        return True
    if bonus_id == BonusId.MEDIKIT and any(perk_active(player, PerkId.DEATH_CLOCK) for player in players):
        return True
    if state.game_mode != GameMode.QUESTS or state.quest_stage_minor != 10:
        return False

    major = state.quest_stage_major
    if bonus_id == BonusId.NUKE:
        return major in (2, 4, 5) or (state.hardcore and major == 3)
    if bonus_id == BonusId.FREEZE:
        return major == 4 or (state.hardcore and major == 2)
    return False


def bonus_pick_random_type(pool: BonusPool, state: GameplayState, players: list[PlayerState]) -> BonusId:
    has_fire_bullets_drop = any(
        entry.bonus_id == BonusId.FIRE_BULLETS and not entry.picked for entry in pool.entries
    )

    for _ in range(101):
        roll = int(state.rng.rand()) % 162 + 1
        bonus_id = _bonus_id_from_roll(roll, state.rng)
        if bonus_id == BonusId.UNUSED:
            continue
        if _bonus_pick_suppressed(
            state=state,
            players=players,
            bonus_id=bonus_id,
            has_fire_bullets_drop=has_fire_bullets_drop,
        ):
            continue
        return bonus_id
    return BonusId.POINTS
