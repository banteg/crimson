from __future__ import annotations

from pathlib import Path
from typing import Any

from crimson.game_modes import GameMode
from crimson.gameplay import GameplayState
from crimson.persistence import save_status
from crimson.weapon_runtime import (
    weapon_pick_random_available,
    weapon_refresh_available,
)
from crimson.weapons import WeaponId


class _SeqRng:
    def __init__(self, values: list[int]) -> None:
        self._values = [int(v) for v in values] or [0]
        self._idx = 0

    def rand(self, *, caller: int | None = None) -> int:
        _ = caller
        if self._idx >= len(self._values):
            return int(self._values[-1])
        value = int(self._values[self._idx])
        self._idx += 1
        return value


def _as_rng(value: object) -> Any:
    return value


def _status_default() -> save_status.GameStatus:
    return save_status.GameStatus(path=Path("game.cfg"), data=save_status.default_status_data(), dirty=False)


def test_weapon_refresh_available_includes_survival_defaults() -> None:
    state = GameplayState()
    state.game_mode = GameMode.SURVIVAL

    weapon_refresh_available(state)

    assert state.weapon_available[WeaponId.PISTOL]
    assert state.weapon_available[WeaponId.ASSAULT_RIFLE]
    assert state.weapon_available[WeaponId.SHOTGUN]
    assert state.weapon_available[WeaponId.SUBMACHINE_GUN]
    assert not state.weapon_available[WeaponId.FLAMETHROWER]


def test_weapon_refresh_available_unlocks_quest_weapon_ids() -> None:
    status = _status_default()
    status.quest_unlock_index = 1

    state = GameplayState()
    state.status = status
    state.game_mode = GameMode.QUESTS

    weapon_refresh_available(state)

    assert state.weapon_available[WeaponId.PISTOL]
    assert state.weapon_available[WeaponId.ASSAULT_RIFLE]
    assert not state.weapon_available[WeaponId.SHOTGUN]


def test_weapon_pick_random_available_enforces_unlocked() -> None:
    status = _status_default()
    status.quest_unlock_index = 0

    state = GameplayState(rng=_as_rng(_SeqRng([1, 0])))
    state.status = status
    state.game_mode = GameMode.QUESTS

    assert weapon_pick_random_available(state) == WeaponId.PISTOL


def test_weapon_pick_random_available_rerolls_used_weapons() -> None:
    status = _status_default()
    status.increment_weapon_usage_for_weapon_id(WeaponId.PISTOL)

    state = GameplayState(rng=_as_rng(_SeqRng([0, 0, 1])))
    state.status = status
    state.game_mode = GameMode.SURVIVAL

    assert weapon_pick_random_available(state) == WeaponId.ASSAULT_RIFLE
