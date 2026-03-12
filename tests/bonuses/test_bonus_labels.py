from __future__ import annotations

import pytest

from crimson.bonuses import BonusId
from crimson.bonuses.payload import BonusWeaponPayload
from crimson.bonuses.pool import BonusEntry, bonus_label_for_entry
from crimson.weapons import WeaponId


@pytest.mark.parametrize(
    ("bonus_id", "amount", "expected_label"),
    [
        (BonusId.POINTS, 1000, "Points: 1000"),
        (BonusId.WEAPON, 1, "Pistol"),
        (BonusId.FREEZE, 0, "Freeze"),
    ],
    ids=["points", "weapon", "meta-name"],
)
def test_bonus_label_for_entry_formats_expected_labels(
    bonus_id: BonusId,
    amount: int,
    expected_label: str,
) -> None:
    entry = BonusEntry(bonus_id=bonus_id, amount=amount)
    assert bonus_label_for_entry(entry) == expected_label


def test_bonus_entry_weapon_payload_preserves_weapon_id_type() -> None:
    entry = BonusEntry(bonus_id=BonusId.WEAPON, amount=int(WeaponId.PISTOL))

    payload = entry.payload

    assert isinstance(payload, BonusWeaponPayload)
    assert payload.weapon_id == WeaponId.PISTOL
