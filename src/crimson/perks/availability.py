from __future__ import annotations

from typing import TYPE_CHECKING

from ..cl_build import ClBuild
from ..game_modes import GameMode
from ..persistence.save_status import GameStatusData
from ..quests import QUESTS
from ..quests.level import QuestLevel
from ..sim.state_types import PERK_COUNT_SIZE
from .ids import PERK_BY_ID, PerkFlags, PerkId

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState


_PERK_BASE_AVAILABLE_MAX_ID = int(PerkId.BONUS_MAGNET)
# 1.9.93's `perks_rebuild_available` always marks these available; 1.9.8 predates them, so its
# `perks_init_database` registers none of them.
_PERKS_AFTER_1_9_8: tuple[PerkId, ...] = (
    PerkId.MAN_BOMB,
    PerkId.LIVING_FORTRESS,
    PerkId.FIRE_CAUGH,
    PerkId.TOUGH_RELOADER,
)


def perk_id_max(cl_build: ClBuild) -> int:
    """Native `perk_id_max`: `perks_init_database` numbers the build's perks from AntiPerk at 0 to Lifeline 50-50.

    1.9.8's Lifeline 50-50 is 53 where the port keeps 1.9.93's 57, so a 1.9.8 roll of 53 lands on Man Bomb;
    neither is ever available, so both reroll.
    """
    last_id = int(max(PERK_BY_ID))
    return last_id - len(_PERKS_AFTER_1_9_8) if cl_build == ClBuild.V1_9_8 else last_id


def build_perk_availability(*, status: GameStatusData, cl_build: ClBuild = ClBuild.V1_9_93) -> list[bool]:
    available = [False] * PERK_COUNT_SIZE
    unlock_index = status.quest_unlock_index

    for perk_id in range(1, _PERK_BASE_AVAILABLE_MAX_ID + 1):
        if 0 <= perk_id < len(available):
            available[perk_id] = True

    if cl_build != ClBuild.V1_9_8:
        for perk_id in _PERKS_AFTER_1_9_8:
            available[perk_id] = True

    if unlock_index > 0:
        quests = QUESTS
        for quest in quests[:unlock_index]:
            perk_id = quest.unlock_perk_id
            if perk_id is not None and 0 < perk_id < len(available):
                available[perk_id] = True

    available[int(PerkId.ANTIPERK)] = False
    return available


def prepare_perk_availability(state: GameplayState) -> None:
    state.perk_available[:] = build_perk_availability(status=state.status, cl_build=state.cl_build)


def perk_can_offer(
    state: GameplayState, perk_id: PerkId, *, game_mode: GameMode, player_count: int,
) -> bool:
    """Return whether `perk_id` is eligible for selection.

    Modeled after `perk_can_offer` (0x0042fb10).
    """

    # Hardcore quest 2-10 blocks poison-related perks.
    if (
        game_mode == GameMode.QUESTS
        and state.hardcore
        and state.quest_level == QuestLevel(2, 10)
        and perk_id in (PerkId.POISON_BULLETS, PerkId.VEINS_OF_POISON, PerkId.PLAGUEBEARER)
    ):
        return False

    meta = PERK_BY_ID.get(perk_id)
    if meta is None:
        return False

    flags = meta.flags
    # Native `perk_can_offer` treats these metadata bits as allow-lists for
    # specific runtime modes, not "only in this mode":
    # - in quest mode, offered perks must have bit 0x1 set
    # - in multiplayer, offered perks must have bit 0x2 set
    # Native only knows 1-2 players and tests `player_count == 2`; the rewrite's
    # 3-4 player extension applies the same allow-list.
    if game_mode == GameMode.QUESTS and (flags & PerkFlags.QUEST_MODE_ALLOWED) == 0:
        return False
    if player_count > 1 and (flags & PerkFlags.MULTIPLAYER_ALLOWED) == 0:
        return False

    return not (meta.prereq and any(state.perks[req] <= 0 for req in meta.prereq))
