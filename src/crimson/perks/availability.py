from __future__ import annotations

from ..game_modes import GameMode
from ..sim.state_types import GameplayState, PlayerState
from .helpers import perk_count_get
from .ids import PERK_BY_ID, PerkFlags, PerkId

_PERK_BASE_AVAILABLE_MAX_ID = int(PerkId.BONUS_MAGNET)  # perks_rebuild_available @ 0x0042fc30
_PERK_ALWAYS_AVAILABLE: tuple[PerkId, ...] = (
    PerkId.MAN_BOMB,
    PerkId.LIVING_FORTRESS,
    PerkId.FIRE_CAUGH,
    PerkId.TOUGH_RELOADER,
)


def perks_rebuild_available(state: GameplayState) -> None:
    """Rebuild quest unlock driven `perk_meta_table[perk_id].available` flags.

    Port of `perks_rebuild_available` (0x0042fc30).
    """

    unlock_index = 0
    if state.status is not None:
        try:
            unlock_index = int(state.status.quest_unlock_index)
        except Exception:
            unlock_index = 0

    if int(state._perk_available_unlock_index) == unlock_index:
        return

    available = state.perk_available
    for idx in range(len(available)):
        available[idx] = False

    for perk_id in range(1, _PERK_BASE_AVAILABLE_MAX_ID + 1):
        if 0 <= perk_id < len(available):
            available[perk_id] = True

    for perk_id in _PERK_ALWAYS_AVAILABLE:
        idx = int(perk_id)
        if 0 <= idx < len(available):
            available[idx] = True

    if unlock_index > 0:
        try:
            from ..quests import all_quests

            quests = all_quests()
        except Exception:
            quests = []

        for quest in quests[:unlock_index]:
            perk_id = int(getattr(quest, "unlock_perk_id", 0) or 0)
            if 0 < perk_id < len(available):
                available[perk_id] = True

    available[int(PerkId.ANTIPERK)] = False
    state._perk_available_unlock_index = unlock_index


def perk_can_offer(
    state: GameplayState, player: PlayerState, perk_id: PerkId, *, game_mode: int, player_count: int
) -> bool:
    """Return whether `perk_id` is eligible for selection.

    Used by `perk_select_random` and modeled after `perk_can_offer` (0x0042fb10).
    """

    if perk_id == PerkId.ANTIPERK:
        return False

    # Hardcore quest 2-10 blocks poison-related perks.
    if (
        int(game_mode) == int(GameMode.QUESTS)
        and state.hardcore
        and int(state.quest_stage_major) == 2
        and int(state.quest_stage_minor) == 10
        and perk_id in (PerkId.POISON_BULLETS, PerkId.VEINS_OF_POISON, PerkId.PLAGUEBEARER)
    ):
        return False

    meta = PERK_BY_ID.get(int(perk_id))
    if meta is None:
        return False

    flags = meta.flags
    # Native `perk_can_offer` treats these metadata bits as allow-lists for
    # specific runtime modes, not "only in this mode":
    # - in quest mode, offered perks must have bit 0x1 set
    # - in two-player mode, offered perks must have bit 0x2 set
    if int(game_mode) == int(GameMode.QUESTS) and (flags & PerkFlags.QUEST_MODE_ALLOWED) == 0:
        return False
    if int(player_count) == 2 and (flags & PerkFlags.TWO_PLAYER_ALLOWED) == 0:
        return False

    if meta.prereq and any(perk_count_get(player, req) <= 0 for req in meta.prereq):
        return False

    return True
