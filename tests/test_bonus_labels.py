from __future__ import annotations

from crimson.bonuses import BonusId
from crimson.gameplay import BonusEntry, bonus_label_for_entry


def test_bonus_label_for_entry_formats_points() -> None:
    entry = BonusEntry(bonus_id=int(BonusId.POINTS), amount=1000)
    assert bonus_label_for_entry(entry) == "Points: 1000"


def test_bonus_label_for_entry_uses_weapon_name() -> None:
    entry = BonusEntry(bonus_id=int(BonusId.WEAPON), amount=1)
    assert bonus_label_for_entry(entry) == "Pistol"


def test_bonus_label_for_entry_uses_meta_name_for_other_types() -> None:
    entry = BonusEntry(bonus_id=int(BonusId.FREEZE), amount=0)
    assert bonus_label_for_entry(entry) == "Freeze"
