from __future__ import annotations

import re
from pathlib import Path

from crimson.creatures.spawn import (
    ALIEN_SPAWNER_TEMPLATES,
    CONSTANT_SPAWN_TEMPLATES,
    GRID_FORMATIONS,
    RING_FORMATIONS,
    TEMPLATE_BUILDERS,
    SpawnId,
)
from crimson.weapon_runtime.fire_recipes import PrimaryPelletsMode, resolve_fire_recipe
from crimson.weapons import WeaponId

REPO_ROOT = Path(__file__).resolve().parents[2]
ZIG_CREATURES = REPO_ROOT / "crimson-zig" / "src" / "runtime" / "creatures.zig"
ZIG_WEAPONS = REPO_ROOT / "crimson-zig" / "src" / "runtime" / "weapons.zig"
ZIG_WEAPON_DATA = REPO_ROOT / "crimson-zig" / "src" / "runtime" / "weapon_data.zig"


def _python_supported_spawn_ids() -> set[int]:
    return {
        *(int(spawn_id) for spawn_id in TEMPLATE_BUILDERS),
        *(int(spawn_id) for spawn_id in ALIEN_SPAWNER_TEMPLATES),
        *(int(spawn_id) for spawn_id in GRID_FORMATIONS),
        *(int(spawn_id) for spawn_id in RING_FORMATIONS),
        *(int(spawn_id) for spawn_id in CONSTANT_SPAWN_TEMPLATES),
    }


def _zig_supported_spawn_ids() -> set[int]:
    source = ZIG_CREATURES.read_text()
    supported = {int(value, 16) for value in re.findall(r"\n\s*0x([0-9a-fA-F]+)\s*=>\s*\{", source)}
    for name in re.findall(r"@intFromEnum\(spawn_mod\.SpawnId\.([a-z0-9_]+)\)\s*=>\s*\{", source):
        supported.add(int(SpawnId[name.upper()]))
    return supported


def _python_supported_fire_weapons() -> set[str]:
    supported: set[str] = set()
    for weapon_id in WeaponId:
        if int(weapon_id) <= 0:
            continue
        try:
            recipe = resolve_fire_recipe(weapon_id, pellet_count=1, fire_bullets_active=False)
        except ValueError:
            continue
        if isinstance(recipe.mode, PrimaryPelletsMode) and recipe.mode.type_id is None:
            continue
        supported.add(weapon_id.name.lower())
    return supported


def _zig_supported_fire_weapons() -> set[str]:
    weapons_source = ZIG_WEAPONS.read_text()
    weapon_data_source = ZIG_WEAPON_DATA.read_text()

    supported = set(re.findall(r"\n\s*\.([a-z0-9_]+)\s*=>\s*\{", weapons_source))
    switch_match = re.search(
        r"pub fn projectileTypeIdFromWeaponId\(weapon_id: WeaponId\) \?ProjectileTypeId \{\n\s*return switch \(weapon_id\) \{(.*?)\n\s*\};\n\}",
        weapon_data_source,
        re.S,
    )
    assert switch_match is not None
    for name, rhs in re.findall(r"\.([a-z0-9_]+)\s*=>\s*([^,\n]+)", switch_match.group(1)):
        if rhs.strip() != "null":
            supported.add(name)
    return supported


def test_python_supported_spawn_templates_are_ported_in_zig() -> None:
    missing = sorted(_python_supported_spawn_ids() - _zig_supported_spawn_ids())
    assert missing == []


def test_python_supported_fire_weapons_are_ported_in_zig() -> None:
    missing = sorted(_python_supported_fire_weapons() - _zig_supported_fire_weapons())
    assert missing == []
