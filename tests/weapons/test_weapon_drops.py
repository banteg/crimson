from __future__ import annotations

from pathlib import Path

from crimson.persistence import save_status
from crimson.sim.gameplay_state import GameplayState
from crimson.weapon_runtime import (
    prepare_weapon_availability,
)
from crimson.weapons import WeaponId


def _status_default() -> save_status.GameStatus:
    return save_status.GameStatus.from_data(
        path=Path("game.cfg"),
        data=save_status.default_status_data(),
        dirty=False,
    )


def test_prepare_weapon_availability_unlocks_splitter_gun_from_full_version_index() -> None:
    status = _status_default()
    status.quest_unlock_index_hardcore = 0x28
    state = GameplayState(status=status)

    prepare_weapon_availability(state)

    assert state.weapon_available[WeaponId.SPLITTER_GUN]
