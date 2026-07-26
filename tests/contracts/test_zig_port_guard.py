from __future__ import annotations

import re
from enum import IntEnum
from pathlib import Path

from crimson.aim_schemes import AimScheme
from crimson.bonuses.ids import BonusId
from crimson.creatures.spawn import (
    ALIEN_SPAWNER_TEMPLATES,
    CONSTANT_SPAWN_TEMPLATES,
    GRID_FORMATIONS,
    RING_FORMATIONS,
    TEMPLATE_BUILDERS,
    SpawnId,
)
from crimson.game_modes import GameMode
from crimson.movement_controls import MovementControlType
from crimson.perks.ids import PerkId
from crimson.projectiles.types import ProjectileTemplateId
from crimson.quests import all_quests
from crimson.quests.level import QUEST_COUNT
from crimson.screens.panels.controls_labels import RebindRowSpec, controls_rebind_plan
from crimson.weapon_runtime.fire_recipes import PrimaryPelletsMode, resolve_fire_recipe
from crimson.weapons import WeaponId

REPO_ROOT = Path(__file__).resolve().parents[2]
ZIG_CREATURES = REPO_ROOT / "crimson-zig" / "src" / "runtime" / "creatures.zig"
ZIG_FIRE_RECIPES = REPO_ROOT / "crimson-zig" / "src" / "runtime" / "fire_recipes.zig"
ZIG_GAME_IDS = REPO_ROOT / "crimson-zig" / "src" / "game_ids.zig"
ZIG_QUEST_SPAWN_DIR = REPO_ROOT / "crimson-zig" / "src" / "quest_spawn"
ZIG_WEAPON_DATA = REPO_ROOT / "crimson-zig" / "src" / "runtime" / "weapon_data.zig"
ZIG_WINDOW_MENU_PANELS = REPO_ROOT / "crimson-zig" / "src" / "window_menu_panels.zig"
ZIG_WINDOW_OPTIONS = REPO_ROOT / "crimson-zig" / "src" / "window_options.zig"


def _python_enum_values(enum_type: type[IntEnum], *, exclude: set[str] | None = None) -> dict[str, int]:
    excluded = exclude or set()
    return {member.name.lower(): int(member) for member in enum_type if member.name.lower() not in excluded}


def _zig_enum_values(enum_name: str) -> dict[str, int]:
    source = ZIG_GAME_IDS.read_text()
    match = re.search(rf"pub const {enum_name} = enum\(i32\) \{{(.*?)\n\}};", source, re.DOTALL)
    assert match is not None

    values: dict[str, int] = {}
    for name, value in re.findall(r"\n\s*([a-z0-9_]+)\s*=\s*(0x[0-9a-fA-F]+|\d+),", match.group(1)):
        values[name] = int(value, 0)
    return values


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
    fire_recipes_source = ZIG_FIRE_RECIPES.read_text()
    weapon_data_source = ZIG_WEAPON_DATA.read_text()

    supported = set(re.findall(r"\n\s*\.([a-z0-9_]+)\s*=>\s*\.?\{", fire_recipes_source))
    switch_match = re.search(
        r"pub fn projectileTypeIdFromWeaponId\(weapon_id: WeaponId\) \?ProjectileTypeId \{\n\s*return switch \(weapon_id\) \{(.*?)\n\s*\};\n\}",
        weapon_data_source,
        re.DOTALL,
    )
    assert switch_match is not None
    for name, rhs in re.findall(r"\.([a-z0-9_]+)\s*=>\s*([^,\n]+)", switch_match.group(1)):
        if rhs.strip() != "null":
            supported.add(name)
    return supported


def _python_quest_start_weapon_ids() -> dict[int, int]:
    quests = all_quests()
    assert len(quests) == QUEST_COUNT
    return {int(quest.level.major) * 100 + int(quest.level.minor): int(quest.start_weapon_id) for quest in quests}


def _zig_quest_start_weapon_ids() -> dict[int, int]:
    weapon_ids = _zig_enum_values("WeaponId")
    by_level: dict[int, int] = {}
    for path in sorted(ZIG_QUEST_SPAWN_DIR.glob("logic_tier*.zig")):
        source = path.read_text()
        for level_key, weapon_name in re.findall(
            r"\.level_key\s*=\s*(\d+),\s*\.start_weapon_id\s*=\s*game_ids\.WeaponId\.([a-z0-9_]+),",
            source,
        ):
            by_level[int(level_key)] = weapon_ids[weapon_name]
    return by_level


def _zig_quest_titles() -> list[str]:
    source = ZIG_WINDOW_MENU_PANELS.read_text()
    match = re.search(r"pub const quest_titles = \[_\]\[\]const u8\{(.*?)\n\};", source, re.DOTALL)
    assert match is not None
    return [
        bytes(value, "utf-8").decode("unicode_escape") for value in re.findall(r'"((?:[^"\\]|\\.)*)"', match.group(1))
    ]


def _normalized_python_rebind_plan(
    *,
    aim_scheme: AimScheme,
    move_mode: MovementControlType,
    player_index: int,
) -> tuple[tuple[str, str, int | None, bool], ...]:
    aim_rows, move_rows, misc_rows = controls_rebind_plan(
        aim_scheme=aim_scheme,
        move_mode=move_mode,
        player_index=player_index,
    )
    return tuple(_normalized_python_rebind_row(row) for row in (*aim_rows, *move_rows, *misc_rows))


def _normalized_python_rebind_row(row: RebindRowSpec) -> tuple[str, str, int | None, bool]:
    return (row.label, row.target.name.lower(), row.target_index, row.axis)


def _zig_rebind_rows_by_name() -> dict[str, tuple[tuple[str, str, int | None, bool], ...]]:
    source = ZIG_WINDOW_OPTIONS.read_text()
    rows_by_name: dict[str, tuple[tuple[str, str, int | None, bool], ...]] = {}
    for name, body in re.findall(r"const (controls_rows_[a-z0-9_]+) = \[_\]RebindRow\{(.*?)\n\};", source, re.DOTALL):
        rows: list[tuple[str, str, int | None, bool]] = []
        for item in re.findall(r"\.\{(.*?)\},", body):
            label_match = re.search(r'\.label\s*=\s*"((?:[^"\\]|\\.)*)"', item)
            target_match = re.search(r"\.target\s*=\s*\.([a-z0-9_]+)", item)
            assert label_match is not None
            assert target_match is not None
            index_match = re.search(r"\.target_index\s*=\s*(\d+)", item)
            rows.append(
                (
                    bytes(label_match.group(1), "utf-8").decode("unicode_escape"),
                    target_match.group(1),
                    int(index_match.group(1)) if index_match is not None else None,
                    ".axis = true" in item,
                ),
            )
        rows_by_name[name] = tuple(rows)
    return rows_by_name


def _normalized_zig_rebind_plan(
    *,
    aim_scheme: AimScheme,
    move_mode: MovementControlType,
    player_index: int,
) -> tuple[tuple[str, str, int | None, bool], ...]:
    rows_by_name = _zig_rebind_rows_by_name()
    name = _zig_rebind_array_name(aim_scheme=aim_scheme, move_mode=move_mode, player_index=player_index)
    return rows_by_name[name]


def _zig_rebind_array_name(*, aim_scheme: AimScheme, move_mode: MovementControlType, player_index: int) -> str:
    prefix = "controls_rows_p1" if player_index == 0 else "controls_rows"

    if move_mode is MovementControlType.MOUSE_POINT_CLICK:
        if aim_scheme is AimScheme.KEYBOARD:
            return f"{prefix}_mouseclick_keyboard"
        if aim_scheme is AimScheme.DUAL_ACTION_PAD:
            return f"{prefix}_mouseclick_dual_pad"
        return f"{prefix}_mouseclick_default"

    if aim_scheme is AimScheme.KEYBOARD:
        if move_mode is MovementControlType.RELATIVE:
            return f"{prefix}_relative_keyboard"
        if move_mode is MovementControlType.STATIC:
            return f"{prefix}_static_keyboard"
        if move_mode is MovementControlType.DUAL_ACTION_PAD:
            return f"{prefix}_move_pad_keyboard"
        return f"{prefix}_other_keyboard"

    if aim_scheme is AimScheme.DUAL_ACTION_PAD:
        if move_mode is MovementControlType.RELATIVE:
            return f"{prefix}_relative_dual_pad"
        if move_mode is MovementControlType.STATIC:
            return f"{prefix}_static_dual_pad"
        if move_mode is MovementControlType.DUAL_ACTION_PAD:
            return f"{prefix}_dual_pad"
        return f"{prefix}_other_dual_pad"

    if move_mode is MovementControlType.RELATIVE:
        return f"{prefix}_relative_default"
    if move_mode is MovementControlType.STATIC:
        return f"{prefix}_static_default"
    if move_mode is MovementControlType.DUAL_ACTION_PAD:
        return f"{prefix}_move_pad_default"
    return f"{prefix}_default"


def test_python_supported_spawn_templates_are_ported_in_zig() -> None:
    missing = sorted(_python_supported_spawn_ids() - _zig_supported_spawn_ids())
    assert missing == []


def test_python_supported_fire_weapons_are_ported_in_zig() -> None:
    missing = sorted(_python_supported_fire_weapons() - _zig_supported_fire_weapons())
    assert missing == []


def test_zig_weapon_ids_match_python_port() -> None:
    assert _zig_enum_values("WeaponId") == _python_enum_values(WeaponId)


def test_zig_bonus_ids_match_python_port() -> None:
    assert _zig_enum_values("BonusId") == _python_enum_values(BonusId)


def test_zig_perk_ids_match_python_port() -> None:
    assert _zig_enum_values("PerkId") == _python_enum_values(PerkId)


def test_zig_game_mode_ids_match_python_playable_modes() -> None:
    assert _zig_enum_values("GameModeId") == _python_enum_values(GameMode, exclude={"demo"})


def test_python_projectile_template_ids_are_known_to_zig() -> None:
    zig_projectiles = _zig_enum_values("ProjectileTypeId")
    missing_or_changed = {
        name: value
        for name, value in _python_enum_values(ProjectileTemplateId).items()
        if zig_projectiles.get(name) != value
    }
    assert missing_or_changed == {}


def test_zig_quest_start_weapons_match_python_port() -> None:
    assert _zig_quest_start_weapon_ids() == _python_quest_start_weapon_ids()


def test_zig_quest_titles_match_python_port() -> None:
    assert _zig_quest_titles() == [quest.title for quest in all_quests()]


def test_zig_controls_rebind_rows_match_python_port() -> None:
    aim_schemes = (
        AimScheme.MOUSE,
        AimScheme.KEYBOARD,
        AimScheme.JOYSTICK,
        AimScheme.MOUSE_RELATIVE,
        AimScheme.DUAL_ACTION_PAD,
        AimScheme.COMPUTER,
    )
    move_modes = (
        MovementControlType.UNKNOWN,
        MovementControlType.RELATIVE,
        MovementControlType.STATIC,
        MovementControlType.DUAL_ACTION_PAD,
        MovementControlType.MOUSE_POINT_CLICK,
        MovementControlType.COMPUTER,
    )

    for player_index in (0, 1):
        for aim_scheme in aim_schemes:
            for move_mode in move_modes:
                assert _normalized_zig_rebind_plan(
                    aim_scheme=aim_scheme,
                    move_mode=move_mode,
                    player_index=player_index,
                ) == _normalized_python_rebind_plan(
                    aim_scheme=aim_scheme,
                    move_mode=move_mode,
                    player_index=player_index,
                )
