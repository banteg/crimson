from __future__ import annotations

from enum import IntEnum

import pytest

from crimson.bonuses.ids import BonusId
from crimson.creatures.spawn import SpawnEnv, build_spawn_plan
from crimson.creatures.spawn_ids import CreatureAiMode, CreatureTypeId, SpawnId
from crimson.creatures.spawn_templates import SPAWN_TEMPLATES
from crimson.game_modes import GameMode
from crimson.perks.ids import PerkId
from crimson.weapons import WEAPON_BY_ID, WEAPON_TABLE, WeaponId
from grim.geom import Vec2
from grim.rand import Crand


def test_weapon_table_invariants() -> None:
    weapon_ids = [int(entry.weapon_id) for entry in WEAPON_TABLE]
    weapon_id_set = set(weapon_ids)

    assert len(weapon_ids) == len(weapon_id_set)
    assert len(WEAPON_BY_ID) == len(WEAPON_TABLE)
    assert set(WEAPON_BY_ID.keys()) == weapon_id_set

    contiguous_holes = {weapon_id for weapon_id in range(min(weapon_ids), max(weapon_ids) + 1) if weapon_id not in weapon_id_set}
    assert contiguous_holes == {34, 35, 36, 37, 38, 39, 40, 46, 47, 48, 49}

    enum_weapon_ids = {int(entry) for entry in WeaponId if entry != WeaponId.NONE}
    assert weapon_id_set <= enum_weapon_ids


def test_spawn_template_child_references_exist() -> None:
    template_ids = {entry.spawn_id for entry in SPAWN_TEMPLATES}
    env = SpawnEnv(
        terrain_width=1024.0,
        terrain_height=1024.0,
        demo_mode_active=False,
        hardcore=False,
        quest_fail_retry_count=0,
    )

    child_template_ids: set[SpawnId] = set()
    for template_id in template_ids:
        plan = build_spawn_plan(template_id, Vec2(512.0, 512.0), 0.0, Crand(0xBEEF), env)
        child_template_ids.update(slot.child_template_id for slot in plan.spawn_slots)

    assert child_template_ids <= template_ids


def _enum_values_are_unique(enum_type: type[IntEnum]) -> bool:
    values = [int(member.value) for member in enum_type]
    return len(values) == len(set(values))


@pytest.mark.parametrize(
    ("enum_type", "enum_label"),
    [
        (WeaponId, "WeaponId"),
        (SpawnId, "SpawnId"),
        (CreatureTypeId, "CreatureTypeId"),
        (CreatureAiMode, "CreatureAiMode"),
        (BonusId, "BonusId"),
        (PerkId, "PerkId"),
        (GameMode, "GameMode"),
    ],
)
def test_non_alias_int_enums_have_unique_values(enum_type: type[IntEnum], enum_label: str) -> None:
    assert _enum_values_are_unique(enum_type), f"{enum_label} has duplicate values"
