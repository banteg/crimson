from __future__ import annotations

from pathlib import Path

import pytest

from crimson.game_modes import GameMode
from crimson.persistence import save_status
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.gameplay_state import GameplayState
from crimson.weapon_runtime import (
    prepare_weapon_availability,
    weapon_pick_random_available,
)
from crimson.weapon_usage import weapon_usage_slot_for_weapon_id
from crimson.weapons import WeaponId
from tests.support.helpers import ScriptedCrand


def _status_default() -> save_status.GameStatus:
    return save_status.GameStatus.from_data(
        path=Path("game.cfg"),
        data=save_status.default_status_data(),
        dirty=False,
    )


def _mark_weapon_used(status: save_status.GameStatus, weapon_id: WeaponId) -> None:
    slot = weapon_usage_slot_for_weapon_id(weapon_id)
    assert slot is not None
    status.increment_weapon_usage_slot(slot)


def test_prepare_weapon_availability_includes_survival_defaults() -> None:
    state = GameplayState()
    state.game_mode = GameMode.SURVIVAL

    prepare_weapon_availability(state)

    assert state.weapon_available[WeaponId.PISTOL]
    assert state.weapon_available[WeaponId.ASSAULT_RIFLE]
    assert state.weapon_available[WeaponId.SHOTGUN]
    assert state.weapon_available[WeaponId.SUBMACHINE_GUN]
    assert not state.weapon_available[WeaponId.FLAMETHROWER]


def test_prepare_weapon_availability_unlocks_quest_weapon_ids() -> None:
    status = _status_default()
    status.quest_unlock_index = 1

    state = GameplayState()
    state.status = status
    state.game_mode = GameMode.QUESTS

    prepare_weapon_availability(state)

    assert state.weapon_available[WeaponId.PISTOL]
    assert state.weapon_available[WeaponId.ASSAULT_RIFLE]
    assert not state.weapon_available[WeaponId.SHOTGUN]


def test_prepare_weapon_availability_unlocks_splitter_gun_from_full_version_index() -> None:
    status = _status_default()
    status.quest_unlock_index_full = 0x28
    state = GameplayState(status=status)

    prepare_weapon_availability(state)

    assert state.weapon_available[WeaponId.SPLITTER_GUN]


def test_weapon_pick_random_available_enforces_unlocked() -> None:
    status = _status_default()
    status.quest_unlock_index = 0

    # The first pick (Assault Rifle) is still locked; the retry picks the Pistol.
    rng = ScriptedCrand([1, 0])
    state = GameplayState(rng=rng)
    state.status = status
    state.game_mode = GameMode.QUESTS
    prepare_weapon_availability(state)

    picked = weapon_pick_random_available(state)

    assert picked == WeaponId.PISTOL
    assert isinstance(picked, WeaponId)
    assert rng.calls == 2


def test_weapon_pick_random_available_rejects_uninitialized_availability() -> None:
    rng = ScriptedCrand()
    state = GameplayState(rng=rng)

    with pytest.raises(RuntimeError, match="call prepare_weapon_availability"):
        weapon_pick_random_available(state)

    assert rng.calls == 0


def test_weapon_pick_random_available_has_no_synthetic_retry_cap() -> None:
    rng = ScriptedCrand([1] * 1001 + [0])
    state = GameplayState(rng=rng)
    state.weapon_available[WeaponId.PISTOL] = True

    assert weapon_pick_random_available(state) == WeaponId.PISTOL
    assert rng.calls == 1002


def test_weapon_pick_random_available_tags_exact_native_callers_on_reroll() -> None:
    status = _status_default()
    _mark_weapon_used(status, WeaponId.PISTOL)

    rng = ScriptedCrand([0, 0, 1])
    state = GameplayState(rng=rng)
    state.status = status
    state.game_mode = GameMode.SURVIVAL
    prepare_weapon_availability(state)

    assert weapon_pick_random_available(state) == WeaponId.ASSAULT_RIFLE
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.WEAPON_PICK_RANDOM_AVAILABLE_PICK,
        RngCallerStatic.WEAPON_PICK_RANDOM_AVAILABLE_REROLL_GATE,
        RngCallerStatic.WEAPON_PICK_RANDOM_AVAILABLE_REROLL_PICK,
    ]
