from __future__ import annotations

from crimson.persistence.save_status import WEAPON_USAGE_COUNT
from crimson.replay.driver.setup import status_from_replay_status_fields
from crimson.weapons import WeaponId


def test_status_from_replay_status_fields_applies_weapon_usage_counts() -> None:
    counts = [0] * WEAPON_USAGE_COUNT
    counts[WeaponId.PISTOL] = 7
    status = status_from_replay_status_fields(
        quest_unlock_index=0,
        quest_unlock_index_full=0,
        weapon_usage_counts=tuple(counts),
    )
    assert status.weapon_usage_count_slot(WeaponId.PISTOL) == 7
