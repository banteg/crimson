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
from crimson.sim.input import PlayerInput
from crimson.weapon_runtime import weapon_assign_player
from crimson.weapons import WEAPON_BY_ID, WeaponId
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.factories import fire_player_weapon

REPO_ROOT = Path(__file__).resolve().parents[2]
ZIG_CREATURES = REPO_ROOT / "crimson-zig" / "src" / "runtime" / "creatures.zig"
ZIG_GAME_IDS = REPO_ROOT / "crimson-zig" / "src" / "game_ids.zig"
ZIG_QUEST_SPAWN_DIR = REPO_ROOT / "crimson-zig" / "src" / "quest_spawn"
ZIG_WEAPONS = REPO_ROOT / "crimson-zig" / "src" / "runtime" / "weapons.zig"
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


def _python_fire_weapons() -> set[str]:
    """Weapons whose native `player_update` fire branch spawns something."""
    fired: set[str] = set()
    for weapon_id in WeaponId:
        if int(weapon_id) <= 0 or weapon_id not in WEAPON_BY_ID:
            continue
        world = make_world()
        player = world.players[0]
        player.pos = Vec2(512.0, 512.0)
        weapon_assign_player(player, weapon_id, state=world.state)
        result = fire_player_weapon(world, player, PlayerInput(fire_down=True, aim=Vec2(600.0, 512.0)), 0.016)
        if result.shot_count > 0:
            fired.add(weapon_id.name.lower())
    return fired


def _zig_fire_weapons() -> set[str]:
    """Weapon ids with an arm in the Zig fire switch (its `else` spawns nothing)."""
    source = ZIG_WEAPONS.read_text()
    switch_start = source.index("switch (weapon_id) {", source.index("fn tryFireWeaponWithGate("))
    arms = source[switch_start : source.index("else =>", switch_start)]
    fired: set[str] = set()
    for labels in re.findall(r"((?:\.[a-z0-9_]+,\s*)*\.[a-z0-9_]+),?\s*=>", arms):
        fired.update(re.findall(r"\.([a-z0-9_]+)", labels))
    return fired


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


def test_zig_fire_switch_matches_python_fire_weapons() -> None:
    assert _zig_fire_weapons() == _python_fire_weapons()


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


def test_zig_standard_pad_codes_match_python() -> None:
    from crimson.gamepad_profile import (
        PAD_PROFILE_AIM_AXIS_CODES,
        PAD_PROFILE_FIRE_CODE,
        PAD_PROFILE_MOVE_AXIS_CODES,
        PAD_PROFILE_PICK_PERK_CODE,
        PAD_PROFILE_RELOAD_CODE,
    )
    from crimson.input_codes import PadCode, input_code_name

    profile_source = (REPO_ROOT / "crimson-zig" / "src" / "gamepad_profile.zig").read_text()
    enum_match = re.search(r"pub const PadCode = enum\(i32\) \{(.*?)\n\n", profile_source, re.DOTALL)
    assert enum_match is not None
    zig_codes = {
        name: int(value, 0) for name, value in re.findall(r"\n\s*([a-z0-9_]+) = (0x[0-9a-fA-F]+),", enum_match.group(1))
    }
    assert zig_codes == {code.name.lower(): int(code) for code in PadCode}

    names_source = (REPO_ROOT / "crimson-zig" / "src" / "input_codes.zig").read_text()
    zig_names = dict(re.findall(r'\n\s*\.([a-z0-9_]+) => "([^"]+)",', names_source))
    for code in PadCode:
        assert zig_names[code.name.lower()] == input_code_name(code)

    for field, code in (
        ("axis_move_y", PAD_PROFILE_MOVE_AXIS_CODES[0]),
        ("axis_move_x", PAD_PROFILE_MOVE_AXIS_CODES[1]),
        ("axis_aim_y", PAD_PROFILE_AIM_AXIS_CODES[0]),
        ("axis_aim_x", PAD_PROFILE_AIM_AXIS_CODES[1]),
        ("fire", PAD_PROFILE_FIRE_CODE),
    ):
        assert f"binds.{field} = PadCode.{PadCode(code).name.lower()}.code();" in profile_source
    assert f"PadCode.{PadCode(PAD_PROFILE_RELOAD_CODE).name.lower()}.code()" in profile_source
    assert f"PadCode.{PadCode(PAD_PROFILE_PICK_PERK_CODE).name.lower()}.code()" in profile_source
