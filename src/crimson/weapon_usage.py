from __future__ import annotations

from .weapons import WeaponId

# Save-status stores 53 u32 entries:
# - slot 0 is unused
# - tracked weapon ids map 1:1 to slots 1..52
# - weapon id 53 has no safe slot in this table
WEAPON_USAGE_SLOT_COUNT = 53
WEAPON_USAGE_TRACKED_WEAPON_ID_MIN = int(WeaponId.PISTOL)
WEAPON_USAGE_TRACKED_WEAPON_ID_MAX = WEAPON_USAGE_SLOT_COUNT - 1


def weapon_usage_slot_for_weapon_id(weapon_id: int) -> int | None:
    """Map a weapon id to save-status usage slot, or `None` if untracked."""

    weapon_id = int(weapon_id)
    if WEAPON_USAGE_TRACKED_WEAPON_ID_MIN <= weapon_id <= WEAPON_USAGE_TRACKED_WEAPON_ID_MAX:
        return weapon_id
    return None
