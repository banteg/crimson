from __future__ import annotations

from typing import Annotated, Any, cast

import msgspec

from .weapons import WeaponId

# Save-status stores 53 u32 entries:
# - slot 0 is unused
# - tracked weapon ids map 1:1 to slots 1..52
# - weapon id 53 has no safe slot in this table
WEAPON_USAGE_SLOT_COUNT = 53
WEAPON_USAGE_TRACKED_WEAPON_ID_MIN = int(WeaponId.PISTOL)
WEAPON_USAGE_TRACKED_WEAPON_ID_MAX = WEAPON_USAGE_SLOT_COUNT - 1

type WeaponUsageCount = Annotated[int, msgspec.Meta(ge=0)]
type WeaponUsageCounts = Annotated[
    tuple[WeaponUsageCount, ...],
    msgspec.Meta(min_length=WEAPON_USAGE_SLOT_COUNT, max_length=WEAPON_USAGE_SLOT_COUNT),
]
ZERO_WEAPON_USAGE_COUNTS: WeaponUsageCounts = tuple(0 for _ in range(WEAPON_USAGE_SLOT_COUNT))


def weapon_usage_slot_for_weapon_id(weapon_id: int) -> int | None:
    """Map a weapon id to save-status usage slot, or `None` if untracked."""

    weapon_id = int(weapon_id)
    if WEAPON_USAGE_TRACKED_WEAPON_ID_MIN <= weapon_id <= WEAPON_USAGE_TRACKED_WEAPON_ID_MAX:
        return weapon_id
    return None


def normalize_weapon_usage_counts(values: object) -> WeaponUsageCounts:
    if not isinstance(values, (list, tuple)):
        return ZERO_WEAPON_USAGE_COUNTS
    normalized: list[int] = [0] * WEAPON_USAGE_SLOT_COUNT
    for idx, value in enumerate(values[:WEAPON_USAGE_SLOT_COUNT]):
        try:
            normalized[idx] = int(cast(Any, value)) & 0xFFFFFFFF
        except (TypeError, ValueError, OverflowError):
            normalized[idx] = 0
    return tuple(normalized)
