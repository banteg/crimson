from __future__ import annotations

from typing import TYPE_CHECKING

from ..game_modes import GameMode
from ..perks import PerkId
from ..perks.helpers import perk_active
from ..rng_caller_static import RngCallerStatic
from .ids import BONUS_BY_ID, BonusId

if TYPE_CHECKING:
    from ..gameplay import GameplayState
    from ..sim.state_types import PlayerState
    from .pool import BonusPool


def _bonus_enabled(bonus_id: BonusId) -> bool:
    meta = BONUS_BY_ID.get(bonus_id)
    if meta is None:
        return False
    return meta.bonus_id != BonusId.UNUSED


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
    # Native reads both shield slots directly, but its global perk helper only
    # reads player 0. Preserve that asymmetry even if the port has more players.
    if bonus_id == BonusId.SHIELD and any(player.shield_timer > 0.0 for player in players[:2]):
        return True
    if bonus_id == BonusId.WEAPON and has_fire_bullets_drop:
        return True
    primary_player = players[0] if players else None
    if (
        bonus_id == BonusId.WEAPON
        and primary_player is not None
        and perk_active(primary_player, PerkId.MY_FAVOURITE_WEAPON)
    ):
        return True
    if bonus_id == BonusId.MEDIKIT and primary_player is not None and perk_active(primary_player, PerkId.DEATH_CLOCK):
        return True
    level = state.quest_level
    if state.game_mode != GameMode.QUESTS or level is None or level.minor != 10:
        return False

    major = level.major
    if bonus_id == BonusId.NUKE:
        return major in (2, 4, 5) or (state.hardcore and major == 3)
    if bonus_id == BonusId.FREEZE:
        return major == 4 or (state.hardcore and major == 2)
    return False


def bonus_pick_random_type(pool: BonusPool, state: GameplayState, players: list[PlayerState]) -> BonusId:
    has_fire_bullets_drop = any(entry.bonus_id == BonusId.FIRE_BULLETS and not entry.picked for entry in pool.entries)

    for _ in range(101):
        roll = state.rng.rand_tagged(RngCallerStatic.BONUS_PICK_RANDOM_TYPE_ROLL) % 162 + 1
        # Mirrors `bonus_pick_random_type` (0x412470) mapping:
        # - roll = rand() % 162 + 1  (1..162)
        # - Points: roll 1..13
        # - Energizer: roll 14 with (rand & 0x3F) == 0, else Weapon
        # - Bucketed ids 3..14 via a 10-step loop; if it would exceed 14, returns 0
        #   to force a reroll (matching the `goto LABEL_18` path leaving `v3 == 0`).
        if roll <= 13:
            bonus_id = BonusId.POINTS
        elif roll == 14:
            if (state.rng.rand_tagged(RngCallerStatic.BONUS_PICK_RANDOM_TYPE_ENERGIZER) & 0x3F) == 0:
                bonus_id = BonusId.ENERGIZER
            else:
                bonus_id = BonusId.WEAPON
        else:
            bucket_offset = roll - 14
            bonus_value = int(BonusId.WEAPON)
            while bucket_offset > 10:
                bucket_offset -= 10
                bonus_value += 1
                if bonus_value >= 15:
                    bonus_value = int(BonusId.UNUSED)
                    break
            bonus_id = BonusId(bonus_value)
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
