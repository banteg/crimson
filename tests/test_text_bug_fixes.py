from __future__ import annotations

from crimson.bonuses import BonusId, bonus_display_description
from crimson.bonuses.pool import BonusEntry, bonus_label_for_entry
from crimson.perks import PerkId, perk_display_name
from crimson.weapons import WeaponId, weapon_display_name


def test_perk_display_name_fixes_fire_caugh_by_default() -> None:
    perk_id = int(PerkId.FIRE_CAUGH)
    assert perk_display_name(perk_id) == "Fire Cough"
    assert perk_display_name(perk_id, preserve_bugs=True) == "Fire Caugh"


def test_weapon_display_name_fixes_spelling_by_default() -> None:
    plague_weapon_id = int(WeaponId.PLAGUE_SPHREADER_GUN)
    lightning_weapon_id = int(WeaponId.LIGHTING_RIFLE)

    assert weapon_display_name(plague_weapon_id) == "Plague Spreader Gun"
    assert weapon_display_name(plague_weapon_id, preserve_bugs=True) == "Plague Sphreader Gun"

    assert weapon_display_name(lightning_weapon_id) == "Lightning Rifle"
    assert weapon_display_name(lightning_weapon_id, preserve_bugs=True) == "Lighting Rifle"


def test_bonus_display_description_fixes_text_by_default() -> None:
    power_up = int(BonusId.WEAPON_POWER_UP)
    fire_bullets = int(BonusId.FIRE_BULLETS)

    assert bonus_display_description(power_up) == "Your fire rate and load time increase for a short period."
    assert bonus_display_description(power_up, preserve_bugs=True) == "Your firerate and load time increase for a short period."

    assert bonus_display_description(fire_bullets) == "For a few seconds -- make them count."
    assert bonus_display_description(fire_bullets, preserve_bugs=True) == "For few seconds -- make them count."


def test_bonus_label_for_entry_uses_typo_fixes_unless_preserving_bugs() -> None:
    entry = BonusEntry(bonus_id=int(BonusId.WEAPON), amount=int(WeaponId.LIGHTING_RIFLE))
    assert bonus_label_for_entry(entry) == "Lightning Rifle"
    assert bonus_label_for_entry(entry, preserve_bugs=True) == "Lighting Rifle"
