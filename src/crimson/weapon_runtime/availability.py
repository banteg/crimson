from __future__ import annotations

from ..game_modes import GameMode
from ..quests import all_quests
from ..replay.types import WEAPON_USAGE_COUNT
from ..sim.state_types import GameplayState
from ..weapons import WeaponId

WEAPON_DROP_ID_COUNT = 0x21  # weapon ids 1..33


def weapon_refresh_available(state: GameplayState) -> None:
    """Rebuild `weapon_table[weapon_id].unlocked` equivalents from quest progression.

    Port of `weapon_refresh_available` (0x00452e40).
    """

    unlock_index = 0
    unlock_index_full = 0
    status = state.status
    if status is not None:
        unlock_index = int(status.quest_unlock_index)
        unlock_index_full = int(status.quest_unlock_index_full)

    game_mode = int(state.game_mode)
    if (
        int(state._weapon_available_game_mode) == game_mode
        and int(state._weapon_available_unlock_index) == unlock_index
        and int(state._weapon_available_unlock_index_full) == unlock_index_full
    ):
        return

    # Clear unlocked flags.
    available = state.weapon_available
    for idx in range(len(available)):
        available[idx] = False

    # Pistol is always available.
    pistol_id = int(WeaponId.PISTOL)
    if 0 <= pistol_id < len(available):
        available[pistol_id] = True

    # Unlock weapons from the quest list (first `quest_unlock_index` entries).
    if unlock_index > 0:
        quests = all_quests()
        for quest in quests[:unlock_index]:
            weapon_id = int(getattr(quest, "unlock_weapon_id", 0) or 0)
            if 0 < weapon_id < len(available):
                available[weapon_id] = True

    # Survival default loadout: Assault Rifle, Shotgun, Submachine Gun.
    if game_mode == int(GameMode.SURVIVAL):
        for weapon_id in (WeaponId.ASSAULT_RIFLE, WeaponId.SHOTGUN, WeaponId.SUBMACHINE_GUN):
            idx = int(weapon_id)
            if 0 <= idx < len(available):
                available[idx] = True

    # Secret unlock: Splitter Gun (weapon id 29) becomes available once the hardcore
    # unlock track reaches stage 5 (quest_unlock_index_full >= 40).
    if (not state.demo_mode_active) and unlock_index_full >= 0x28:
        splitter_id = int(WeaponId.SPLITTER_GUN)
        if 0 <= splitter_id < len(available):
            available[splitter_id] = True

    state._weapon_available_game_mode = game_mode
    state._weapon_available_unlock_index = unlock_index
    state._weapon_available_unlock_index_full = unlock_index_full


def weapon_pick_random_available(state: GameplayState) -> int:
    """Select a random available weapon id (1..33).

    Port of `weapon_pick_random_available` (0x00452cd0).
    """

    weapon_refresh_available(state)
    status = state.status

    for _ in range(1000):
        base_rand = int(state.rng.rand())
        weapon_id = base_rand % WEAPON_DROP_ID_COUNT + 1

        # Bias: used weapons have a 50% chance to reroll once.
        if status is not None and 0 <= weapon_id < WEAPON_USAGE_COUNT and status.weapon_usage_count(weapon_id) != 0:
            if (int(state.rng.rand()) & 1) == 0:
                base_rand = int(state.rng.rand())
                weapon_id = base_rand % WEAPON_DROP_ID_COUNT + 1

        if not (0 <= weapon_id < len(state.weapon_available)):
            continue
        if not state.weapon_available[weapon_id]:
            continue

        # Quest 5-10 special-case: suppress Ion Cannon.
        if (
            int(state.game_mode) == int(GameMode.QUESTS)
            and int(state.quest_stage_major) == 5
            and int(state.quest_stage_minor) == 10
            and weapon_id == int(WeaponId.ION_CANNON)
        ):
            continue

        return weapon_id

    return int(WeaponId.PISTOL)
