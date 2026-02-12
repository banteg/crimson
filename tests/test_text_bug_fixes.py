from __future__ import annotations

from crimson.bonuses import BonusId, bonus_display_description
from crimson.bonuses.pool import BonusEntry, bonus_label_for_entry
from crimson.perks import PerkId, perk_display_description, perk_display_name
from crimson.weapons import WeaponId, weapon_display_name


def test_perk_display_name_fixes_fire_caugh_by_default() -> None:
    perk_id = int(PerkId.FIRE_CAUGH)
    assert perk_display_name(perk_id) == "Fire Cough"
    assert perk_display_name(perk_id, preserve_bugs=True) == "Fire Caugh"


def test_weapon_display_name_fixes_spelling_by_default() -> None:
    plague_weapon_id = int(WeaponId.PLAGUE_SPHREADER_GUN)
    lightning_weapon_id = int(WeaponId.LIGHTING_RIFLE)
    fire_bullets_weapon_id = int(WeaponId.FIRE_BULLETS)

    assert weapon_display_name(plague_weapon_id) == "Plague Spreader Gun"
    assert weapon_display_name(plague_weapon_id, preserve_bugs=True) == "Plague Sphreader Gun"

    assert weapon_display_name(lightning_weapon_id) == "Lightning Rifle"
    assert weapon_display_name(lightning_weapon_id, preserve_bugs=True) == "Lighting Rifle"

    assert weapon_display_name(fire_bullets_weapon_id) == "Fire Bullets"
    assert weapon_display_name(fire_bullets_weapon_id, preserve_bugs=True) == "Fire bullets"


def test_perk_display_description_fixes_grammar_by_default() -> None:
    anxious_loader = int(PerkId.ANXIOUS_LOADER)
    perk_expert = int(PerkId.PERK_EXPERT)
    dodger = int(PerkId.DODGER)
    ninja = int(PerkId.NINJA)
    living_fortress = int(PerkId.LIVING_FORTRESS)

    assert "waiting for your gun" in perk_display_description(anxious_loader)
    assert "waiting your gun" in perk_display_description(anxious_loader, preserve_bugs=True)

    assert "laying around" in perk_display_description(perk_expert)
    assert "attacks you, you have a chance" in perk_display_description(dodger)
    assert "attacks you you have a chance" in perk_display_description(dodger, preserve_bugs=True)

    assert "have a really hard time" in perk_display_description(ninja)
    assert "have really hard time" in perk_display_description(ninja, preserve_bugs=True)

    fixed_lf = perk_display_description(living_fortress)
    bugged_lf = perk_display_description(living_fortress, preserve_bugs=True)
    assert "There comes a time" in fixed_lf
    assert "Being a living fortress comes with extra benefits" in fixed_lf
    assert "You do more damage the longer you stand still." in fixed_lf
    assert "It comes a time" in bugged_lf
    assert "Being living fortress not moving" in bugged_lf
    assert "You do the more damage" in bugged_lf


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
