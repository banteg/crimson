from __future__ import annotations

from typing import TYPE_CHECKING

from ..game_modes import GameMode
from ..persistence.save_status import GameStatus
from ..quests import all_quests
from ..quests.level import QuestLevel
from ..rng_caller_static import RngCallerStatic
from ..weapon_usage import weapon_usage_slot_for_weapon_id
from ..weapons import WEAPON_TABLE, WeaponId

if TYPE_CHECKING:
    from crimson.sim.gameplay_state import GameplayState


WEAPON_DROP_ID_COUNT = 0x21  # weapon ids 1..33
WEAPON_AVAILABLE_COUNT = max(int(entry.weapon_id) for entry in WEAPON_TABLE) + 1


def build_weapon_availability(
    *,
    status: GameStatus | None,
    game_mode: GameMode,
) -> list[bool]:
    available = [False] * WEAPON_AVAILABLE_COUNT
    unlock_index = 0
    unlock_index_full = 0
    if status is not None:
        unlock_index = status.quest_unlock_index
        unlock_index_full = status.quest_unlock_index_full

    pistol_id = WeaponId.PISTOL
    if 0 <= pistol_id < len(available):
        available[pistol_id] = True

    if unlock_index > 0:
        quests = all_quests()
        for quest in quests[:unlock_index]:
            weapon_id = quest.unlock_weapon_id
            if weapon_id is not None and 0 < weapon_id < len(available):
                available[weapon_id] = True

    if game_mode == GameMode.SURVIVAL:
        for weapon_id in (WeaponId.ASSAULT_RIFLE, WeaponId.SHOTGUN, WeaponId.SUBMACHINE_GUN):
            if 0 <= weapon_id < len(available):
                available[weapon_id] = True

    if unlock_index_full >= 0x28:
        splitter_id = WeaponId.SPLITTER_GUN
        if 0 <= splitter_id < len(available):
            available[splitter_id] = True

    return available


def prepare_weapon_availability(state: GameplayState) -> None:
    state.weapon_available[:] = build_weapon_availability(
        status=state.status,
        game_mode=state.game_mode,
    )


def weapon_pick_random_available(state: GameplayState) -> WeaponId:
    """Select a random available weapon id.

    Port of `weapon_pick_random_available` (0x00452cd0).
    """

    status = state.status
    suppress_ion_cannon = state.game_mode == GameMode.QUESTS and state.quest_level == QuestLevel(5, 10)
    has_eligible_weapon = any(
        weapon_id < len(state.weapon_available)
        and state.weapon_available[weapon_id]
        and not (suppress_ion_cannon and weapon_id == WeaponId.ION_CANNON)
        for weapon_id in range(1, WEAPON_DROP_ID_COUNT + 1)
    )
    if not has_eligible_weapon:
        raise RuntimeError("weapon availability has no eligible drop; call prepare_weapon_availability()")

    while True:
        base_rand = state.rng.rand_tagged(RngCallerStatic.WEAPON_PICK_RANDOM_AVAILABLE_PICK)
        weapon_id = WeaponId(base_rand % WEAPON_DROP_ID_COUNT + 1)

        # Bias: used weapons have a 50% chance to reroll once.
        if status is not None:
            usage_slot = weapon_usage_slot_for_weapon_id(weapon_id)
            if (  # noqa: SIM102 - preserve the native reroll gate and RNG draw shape
                usage_slot is not None and status.weapon_usage_count_slot(usage_slot) != 0
            ):
                if (state.rng.rand_tagged(RngCallerStatic.WEAPON_PICK_RANDOM_AVAILABLE_REROLL_GATE) & 1) == 0:
                    base_rand = state.rng.rand_tagged(RngCallerStatic.WEAPON_PICK_RANDOM_AVAILABLE_REROLL_PICK)
                    weapon_id = WeaponId(base_rand % WEAPON_DROP_ID_COUNT + 1)

        if not (0 <= weapon_id < len(state.weapon_available)):
            continue
        if not state.weapon_available[weapon_id]:
            continue

        # Quest 5-10 special-case: suppress Ion Cannon.
        if suppress_ion_cannon and weapon_id == WeaponId.ION_CANNON:
            continue

        return weapon_id
