from __future__ import annotations

import pytest

from crimson.projectiles.types import ProjectileTypeId
from crimson.weapons import (
    WEAPON_PROJECTILE_TYPE_IDS,
    WeaponId,
    projectile_type_id_for_weapon_id,
)


def test_weapon_projectile_type_mapping() -> None:
    # Known mappings from the decompile (`player_fire_weapon`).
    cases = {
        1: 0x01,  # Pistol
        2: 0x02,  # Assault Rifle
        3: 0x03,  # Shotgun
        4: 0x03,  # Sawed-off Shotgun
        5: 0x05,  # Submachine Gun
        6: 0x06,  # Gauss Gun
        7: 0x01,  # Mean Minigun
        9: 0x09,  # Plasma Rifle
        10: 0x09,  # Multi-Plasma (primary)
        11: 0x0B,  # Plasma Minigun
        14: 0x0B,  # Plasma Shotgun
        19: 0x13,  # Pulse Gun
        20: 0x03,  # Jackhammer
        21: 0x15,  # Ion Rifle
        22: 0x16,  # Ion Minigun
        23: 0x17,  # Ion Cannon
        24: 0x18,  # Shrinkifier 5k
        25: 0x19,  # Blade Gun
        28: 0x1C,  # Plasma Cannon
        29: 0x1D,  # Splitter Gun
        30: 0x06,  # Gauss Shotgun
        31: 0x16,  # Ion Shotgun
        41: 0x29,  # Plague Spreader Gun
        43: 0x2B,  # Rainbow Gun
        45: 0x2D,  # Fire Bullets
    }
    for weapon_id, type_id in cases.items():
        assert projectile_type_id_for_weapon_id(WeaponId(weapon_id)) == ProjectileTypeId(type_id)

    assert WEAPON_PROJECTILE_TYPE_IDS[WeaponId.MULTI_PLASMA] == (
        ProjectileTypeId.PLASMA_RIFLE,
        ProjectileTypeId.PLASMA_MINIGUN,
    )


def test_non_projectile_weapons_raise() -> None:
    # Non-projectile paths: particles or secondary projectile pool.
    for weapon_id in (8, 12, 13, 15, 16, 17, 18, 42):
        weapon = WeaponId(weapon_id)
        with pytest.raises(ValueError, match="weapon has no primary projectile type"):
            projectile_type_id_for_weapon_id(weapon)
