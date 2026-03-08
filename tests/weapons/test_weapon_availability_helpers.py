from __future__ import annotations

from crimson.game_modes import GameMode
from crimson.weapon_runtime.availability import unlocked_weapon_ids, weapon_available_mask
from crimson.weapons import WeaponId


def test_weapon_available_mask_adds_survival_starters(make_game_state) -> None:
    state = make_game_state()

    available = weapon_available_mask(
        status=state.status,
        game_mode=GameMode.SURVIVAL,
        demo_mode_active=state.demo_enabled,
    )

    assert available[int(WeaponId.PISTOL)] is True
    assert available[int(WeaponId.ASSAULT_RIFLE)] is True
    assert available[int(WeaponId.SHOTGUN)] is True
    assert available[int(WeaponId.SUBMACHINE_GUN)] is True


def test_unlocked_weapon_ids_include_splitter_when_full_unlock_track_reached(make_game_state) -> None:
    state = make_game_state(demo_enabled=False)
    state.status.quest_unlock_index_full = 40

    weapon_ids = unlocked_weapon_ids(
        status=state.status,
        game_mode=GameMode.QUESTS,
        demo_mode_active=state.demo_enabled,
    )

    assert WeaponId.SPLITTER_GUN in weapon_ids
