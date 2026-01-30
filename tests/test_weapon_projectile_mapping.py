from __future__ import annotations

from crimson.weapons import (
    projectile_type_id_from_weapon_id,
    projectile_type_ids_from_weapon_id,
)


def test_weapon_projectile_type_mapping() -> None:
    # Known mappings from docs/structs/projectile.md.
    cases = {
        1: 0x00,  # Pistol (inferred)
        2: 0x01,  # Assault Rifle
        3: 0x02,  # Shotgun
        4: 0x03,  # Sawed-off Shotgun
        5: 0x03,  # Submachine Gun
        6: 0x05,  # Gauss Gun
        7: 0x06,  # Mean Minigun
        8: 0x01,  # Flamethrower
        10: 0x09,  # Multi-Plasma
        11: 0x09,  # Plasma Minigun (primary)
        12: 0x0B,  # Rocket Launcher
        15: 0x0B,  # Blow Torch
        20: 0x13,  # Jackhammer
        21: 0x03,  # Ion Rifle
        22: 0x15,  # Ion Minigun
        23: 0x16,  # Ion Cannon
        24: 0x17,  # Shrinkifier 5k
        25: 0x18,  # Blade Gun
        26: 0x19,  # Spider Plasma
        28: 0x1B,  # Plasma Cannon (inferred)
        29: 0x1C,  # Splitter Gun
        30: 0x1D,  # Gauss Shotgun
        31: 0x06,  # Ion Shotgun
        32: 0x16,  # Flameburst
        42: 0x29,  # Bubblegun
        44: 0x2B,  # Grim Weapon
        45: 0x2D,  # Fire Bullets
    }
    for weapon_id, type_id in cases.items():
        assert projectile_type_id_from_weapon_id(weapon_id) == type_id

    assert projectile_type_ids_from_weapon_id(11) == (0x09, 0x0B)


def test_non_projectile_weapons_return_none() -> None:
    # Non-projectile paths: particles or secondary projectile pool.
    for weapon_id in (9, 13, 14, 16, 17, 18, 19, 43):
        assert projectile_type_id_from_weapon_id(weapon_id) is None
        assert projectile_type_ids_from_weapon_id(weapon_id) == ()
