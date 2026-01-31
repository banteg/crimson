from __future__ import annotations

from pathlib import Path

from crimson.game_modes import GameMode
from crimson.gameplay import GameplayState, weapon_pick_random_available, weapon_refresh_available
from crimson.persistence import save_status
from crimson.weapons import WeaponId


class _SeqRng:
    def __init__(self, values: list[int]) -> None:
        self._values = [int(v) for v in values] or [0]
        self._idx = 0

    def rand(self) -> int:
        if self._idx >= len(self._values):
            return int(self._values[-1])
        value = int(self._values[self._idx])
        self._idx += 1
        return value


def _status_default() -> save_status.GameStatus:
    return save_status.GameStatus(path=Path("game.cfg"), data=save_status.default_status_data(), dirty=False)


def test_weapon_refresh_available_includes_survival_defaults() -> None:
    state = GameplayState()
    state.game_mode = int(GameMode.SURVIVAL)

    weapon_refresh_available(state)

    assert state.weapon_available[int(WeaponId.PISTOL)]
    assert state.weapon_available[int(WeaponId.ASSAULT_RIFLE)]
    assert state.weapon_available[int(WeaponId.SHOTGUN)]
    assert state.weapon_available[int(WeaponId.SUBMACHINE_GUN)]
    assert not state.weapon_available[int(WeaponId.FLAMETHROWER)]


def test_weapon_refresh_available_unlocks_quest_weapon_ids() -> None:
    status = _status_default()
    status.quest_unlock_index = 1

    state = GameplayState()
    state.status = status
    state.game_mode = int(GameMode.QUESTS)

    weapon_refresh_available(state)

    assert state.weapon_available[int(WeaponId.PISTOL)]
    assert state.weapon_available[int(WeaponId.ASSAULT_RIFLE)]
    assert not state.weapon_available[int(WeaponId.SHOTGUN)]


def test_weapon_pick_random_available_enforces_unlocked() -> None:
    status = _status_default()
    status.quest_unlock_index = 0

    state = GameplayState(rng=_SeqRng([1, 0]))
    state.status = status
    state.game_mode = int(GameMode.QUESTS)

    assert weapon_pick_random_available(state) == int(WeaponId.PISTOL)


def test_weapon_pick_random_available_rerolls_used_weapons() -> None:
    status = _status_default()
    status.increment_weapon_usage(int(WeaponId.PISTOL))

    state = GameplayState(rng=_SeqRng([0, 0, 1]))
    state.status = status
    state.game_mode = int(GameMode.SURVIVAL)

    assert weapon_pick_random_available(state) == int(WeaponId.ASSAULT_RIFLE)

