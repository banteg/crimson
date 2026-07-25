from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


def _load_importer():
    path = Path(__file__).parents[1] / "scripts" / "binja_import_maps.py"
    spec = importlib.util.spec_from_file_location("binja_import_maps_test", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _FakeView:
    def __init__(self, containing=(), prefix=b""):
        self._functions = {}
        self._containing = list(containing)
        self._prefix = prefix
        self.created = []
        self.removed = []

    def get_function_at(self, addr):
        return self._functions.get(addr)

    def get_functions_containing(self, _addr):
        return list(self._containing)

    def create_user_function(self, addr):
        self.created.append(addr)
        self._functions[addr] = SimpleNamespace(start=addr)

    def remove_function(self, func):
        self.removed.append(func)
        self._containing.remove(func)

    def read(self, _addr, size):
        return self._prefix[:size]


class _FakeTypeView:
    def __init__(self):
        self.types = {"projectile_t": "old"}
        self.actions = []

    def get_type_by_name(self, name):
        return self.types.get(str(name))

    def undefine_user_type(self, name):
        self.actions.append(("undefine", str(name)))
        self.types.pop(str(name), None)

    def define_user_type(self, name, type_obj):
        self.actions.append(("define", str(name), type_obj))
        self.types[str(name)] = type_obj


def test_find_repo_root_walks_database_ancestors(tmp_path):
    importer = _load_importer()
    repo_root = tmp_path / "repo"
    database_dir = repo_root / "analysis" / "binary_ninja"
    (repo_root / "analysis" / "ghidra" / "maps").mkdir(parents=True)
    database_dir.mkdir(parents=True)
    database_path = database_dir / "crimsonland.exe.bndb"
    view = SimpleNamespace(
        file=SimpleNamespace(
            original_filename=str(database_path),
            filename=str(database_path),
        ),
    )

    assert importer._find_repo_root(view) == repo_root


def test_resolve_creates_direct_jump_target_without_create_flag(monkeypatch):
    importer = _load_importer()
    wrapper = SimpleNamespace(start=0x1000)
    view = _FakeView([wrapper])
    monkeypatch.setattr(importer, "_is_direct_jump_wrapper", lambda _bv, _func, _addr: True)

    func, created = importer._resolve_function_for_name_row(
        view,
        {"name": "initializer_body"},
        0x1010,
    )

    assert created is True
    assert func.start == 0x1010
    assert view.created == [0x1010]
    assert view.removed == []


def test_resolve_splits_explicit_padding_prefixed_function(monkeypatch):
    importer = _load_importer()
    padding_function = SimpleNamespace(start=0x2000)
    view = _FakeView([padding_function], prefix=b"\x90" * 8)
    monkeypatch.setattr(importer, "_is_direct_jump_wrapper", lambda _bv, _func, _addr: False)

    func, created = importer._resolve_function_for_name_row(
        view,
        {"name": "empty_destructor", "create": True},
        0x2008,
    )

    assert created is True
    assert func.start == 0x2008
    assert view.removed == [padding_function]
    assert view.created == [0x2008]


def test_resolve_does_not_create_unmarked_interior_function(monkeypatch):
    importer = _load_importer()
    containing = SimpleNamespace(start=0x3000)
    view = _FakeView([containing], prefix=b"\x55\x8b\xec")
    monkeypatch.setattr(importer, "_is_direct_jump_wrapper", lambda _bv, _func, _addr: False)

    func, created = importer._resolve_function_for_name_row(
        view,
        {"name": "interior"},
        0x3003,
    )

    assert func is None
    assert created is False
    assert view.created == []
    assert view.removed == []


def test_resolve_rejects_explicit_non_padding_interior_function(monkeypatch):
    importer = _load_importer()
    containing = SimpleNamespace(start=0x4000)
    view = _FakeView([containing], prefix=b"\x55\x8b\xec")
    monkeypatch.setattr(importer, "_is_direct_jump_wrapper", lambda _bv, _func, _addr: False)

    with pytest.raises(RuntimeError, match="inside an existing function"):
        importer._resolve_function_for_name_row(
            view,
            {"name": "unsafe_split", "create": True},
            0x4003,
        )


def test_authoritative_repo_type_replaces_complete_database_type(monkeypatch):
    importer = _load_importer()
    monkeypatch.setattr(
        importer,
        "_should_replace_incomplete_type",
        lambda _existing, _replacement: False,
    )

    assert importer._should_replace_repo_type(
        "ui_menu_item_subtemplate_slot_t",
        object(),
        object(),
    )
    assert importer._should_replace_repo_type(
        "FILE",
        object(),
        object(),
    )
    assert importer._should_replace_repo_type(
        "projectile_t",
        object(),
        object(),
    )
    assert importer._should_replace_repo_type(
        "projectile_pool_t",
        object(),
        object(),
    )
    assert importer._should_replace_repo_type(
        "particle_t",
        object(),
        object(),
    )
    assert importer._should_replace_repo_type(
        "particle_binja_t",
        object(),
        object(),
    )
    assert importer._should_replace_repo_type(
        "fx_queue_entry_t",
        object(),
        object(),
    )
    assert importer._should_replace_repo_type(
        "fx_queue_entry_binja_t",
        object(),
        object(),
    )
    assert importer._should_replace_repo_type(
        "creature_t",
        object(),
        object(),
    )
    assert importer._should_replace_repo_type(
        "creature_binja_t",
        object(),
        object(),
    )
    assert importer._should_replace_repo_type(
        "creature_type_t",
        object(),
        object(),
    )
    assert importer._should_replace_repo_type(
        "creature_type_table_t",
        object(),
        object(),
    )
    assert importer._should_replace_repo_type(
        "game_status_t",
        object(),
        object(),
    )
    assert importer._should_replace_repo_type(
        "weapon_storage_entry_t",
        object(),
        object(),
    )
    assert importer._should_replace_repo_type(
        "weapon_storage_table_t",
        object(),
        object(),
    )
    assert importer._should_replace_repo_type(
        "mod_interface_t",
        object(),
        object(),
    )
    assert importer._should_replace_repo_type(
        "quest_spawn_entry_t",
        object(),
        object(),
    )
    assert importer._should_replace_repo_type(
        "quest_spawn_pair_binja_t",
        object(),
        object(),
    )
    assert importer._should_replace_repo_type(
        "quest_spawn_entries_binja_t",
        object(),
        object(),
    )
    assert importer._should_replace_repo_type(
        "ui_element_vertex_t",
        object(),
        object(),
    )
    assert importer._should_replace_repo_type(
        "ui_element_vertex_binja_t",
        object(),
        object(),
    )
    assert importer._should_replace_repo_type(
        "ui_element_t",
        object(),
        object(),
    )
    assert importer._should_replace_repo_type(
        "ui_element_binja_t",
        object(),
        object(),
    )
    assert importer._should_replace_repo_type(
        "ui_menu_item_subtemplate_slot_binja_t",
        object(),
        object(),
    )
    assert importer._should_replace_repo_type(
        "bonus_hud_slot_t",
        object(),
        object(),
    )
    assert importer._should_replace_repo_type(
        "bonus_hud_slot_table_t",
        object(),
        object(),
    )
    assert importer._should_replace_repo_type(
        "bonus_hud_slot_binja_t",
        object(),
        object(),
    )
    assert not importer._should_replace_repo_type(
        "unrelated_complete_type",
        object(),
        object(),
    )


def test_define_or_replace_removes_silent_duplicate_first(monkeypatch):
    importer = _load_importer()
    monkeypatch.setattr(importer, "bn", object())
    view = _FakeTypeView()

    assert importer._define_or_replace_user_type(
        view,
        "projectile_t",
        "flat",
    )
    assert view.types["projectile_t"] == "flat"
    assert view.actions == [
        ("undefine", "projectile_t"),
        ("define", "projectile_t", "flat"),
    ]


def test_repo_type_view_overrides_use_flat_decompiler_records():
    importer = _load_importer()

    assert importer._REPO_TYPE_VIEW_OVERRIDES["projectile_t"] == (
        "projectile_binja_t"
    )
    assert importer._REPO_TYPE_VIEW_OVERRIDES["creature_t"] == (
        "creature_binja_t"
    )
    assert importer._REPO_TYPE_VIEW_OVERRIDES["particle_t"] == (
        "particle_binja_t"
    )
    assert importer._REPO_TYPE_VIEW_OVERRIDES["fx_queue_entry_t"] == (
        "fx_queue_entry_binja_t"
    )
    assert importer._REPO_TYPE_VIEW_OVERRIDES[
        "ui_menu_item_subtemplate_slot_t"
    ] == ("ui_menu_item_subtemplate_slot_binja_t")
    assert importer._REPO_TYPE_VIEW_OVERRIDES["ui_element_vertex_t"] == (
        "ui_element_vertex_binja_t"
    )
    assert importer._REPO_TYPE_VIEW_OVERRIDES["ui_element_t"] == (
        "ui_element_binja_t"
    )
    assert importer._REPO_TYPE_VIEW_OVERRIDES["bonus_hud_slot_t"] == (
        "bonus_hud_slot_binja_t"
    )
    assert importer._REPO_TYPE_ARRAY_VIEW_OVERRIDES[
        "bonus_hud_slot_table_t"
    ] == ("bonus_hud_slot_binja_t", 0x10)


def test_quest_builder_signature_uses_array_presentation_view():
    importer = _load_importer()

    assert importer._presentation_signature(
        "quest_build_fallback",
        "void quest_build_fallback(quest_spawn_entry_t *entries, int *count)",
    ) == (
        "void quest_build_fallback("
        "quest_spawn_entries_binja_t *table, int *count)"
    )
    assert importer._presentation_signature(
        "quest_start_selected",
        "void quest_start_selected(int major, int minor)",
    ) == "void quest_start_selected(int major, int minor)"
    assert importer._presentation_signature(
        "quest_build_everred_pastures",
        "void quest_build_everred_pastures("
        "quest_spawn_entry_t *entries, int *count)",
    ) == (
        "void quest_build_everred_pastures("
        "quest_spawn_entry_t *entries, int *count)"
    )


def test_data_map_preserves_recovered_pool_extents():
    map_path = (
        Path(__file__).parents[1]
        / "analysis"
        / "ghidra"
        / "maps"
        / "data_map.json"
    )
    rows = json.loads(map_path.read_text())["entries"]
    types_by_name = {
        row["name"]: row.get("type")
        for row in rows
        if row.get("program") == "crimsonland.exe" and row.get("name")
    }

    assert types_by_name["effect_uv_strip16"] == "uv2f_t[16]"
    assert types_by_name["effect_uv2"] == "uv2f_t[4]"
    assert types_by_name["effect_uv4"] == "uv2f_t[16]"
    assert types_by_name["effect_uv8"] == "uv2f_t[64]"
    assert types_by_name["effect_uv16"] == "uv2f_t[256]"
    assert types_by_name["fx_queue"] == "fx_queue_entry_t[128]"
    assert types_by_name["particle_pool"] == "particle_t[128]"
    assert types_by_name["creature_pool"] == "creature_t[384]"
    assert types_by_name["highscore_table"] == "highscore_record_t[100]"
    assert types_by_name["quest_selected_meta"] == "quest_meta_t[50]"
    assert (
        types_by_name["creature_spawn_slot_table"]
        == "creature_spawn_slot_t[32]"
    )
    assert types_by_name["bonus_meta_table"] == "bonus_meta_t[15]"
    assert types_by_name["survival_recent_death_pos"] == "vec2f_t[3]"
    assert types_by_name["sprite_effect_pool"] == "sprite_effect_t[384]"
    assert types_by_name["perk_meta_table"] == "perk_meta_t[128]"
    assert types_by_name["music_entry_table"] == "music_entry_t[128]"
    assert types_by_name["sfx_entry_table"] == "sfx_entry_t[128]"
    assert types_by_name["effect_free_list_head"] == "effect_entry_t *"
    assert (
        types_by_name["tutorial_hint_bonus_ptr"]
        == "tutorial_bonus_carrier_binja_t *"
    )
    assert types_by_name["ui_element_table_end"] == "ui_element_t *[41]"


def test_importer_preserves_ui_element_pointer_table_aggregate():
    importer = _load_importer()

    assert importer._FORCED_DATA_AGGREGATES == frozenset(
        {"ui_element_table_end"},
    )


def test_resolve_data_type_accepts_array_typedef(monkeypatch):
    importer = _load_importer()
    array_type = object()
    view = SimpleNamespace(
        get_type_by_name=lambda name: (
            array_type if str(name) == "bonus_hud_slot_table_t" else None
        ),
    )
    monkeypatch.setattr(importer, "_seed_common_types", lambda _bv: None)

    assert importer._resolve_data_type(
        view,
        "bonus_hud_slot_table_t",
    ) is array_type


def test_written_variable_at_resolves_unique_ssa_definition():
    importer = _load_importer()
    variable = object()
    instruction = SimpleNamespace(
        address=0x4502F1,
        vars_written=[SimpleNamespace(var=variable)],
    )
    function = SimpleNamespace(
        mlil=SimpleNamespace(ssa_form=[[instruction]]),
    )

    assert importer._written_variable_at(function, 0x4502F1) is variable


def test_written_variable_at_rejects_missing_definition():
    importer = _load_importer()
    function = SimpleNamespace(
        mlil=SimpleNamespace(ssa_form=[]),
    )

    with pytest.raises(LookupError, match="expected one written variable"):
        importer._written_variable_at(function, 0x4502F1)


def test_apply_function_local_types_is_idempotent(monkeypatch):
    importer = _load_importer()
    local_type = object()
    variable = SimpleNamespace(
        name="menu_item_vertex0_element",
        type=local_type,
    )
    instruction = SimpleNamespace(
        address=0x4502F1,
        vars_written=[SimpleNamespace(var=variable)],
    )

    class FakeFunction:
        mlil = SimpleNamespace(ssa_form=[[instruction]])

        def __init__(self):
            self.created = []

        def is_var_user_defined(self, _var):
            return True

        def create_user_var(self, var, var_type, name):
            self.created.append((var, var_type, name))

    function = FakeFunction()
    monkeypatch.setattr(
        importer,
        "_resolve_data_type",
        lambda _bv, _type_text: local_type,
    )

    count = importer._apply_function_local_types(
        object(),
        function,
        [
            {
                "address": "0x004502f1",
                "name": "menu_item_vertex0_element",
                "type": "ui_element_t *",
            },
        ],
    )

    assert count == 1
    assert function.created == []


def test_name_map_preserves_recovered_core_pointer_signatures():
    map_path = (
        Path(__file__).parents[1]
        / "analysis"
        / "ghidra"
        / "maps"
        / "name_map.json"
    )
    rows = json.loads(map_path.read_text())
    signatures_by_name = {
        row["name"]: row.get("signature")
        for row in rows
        if row.get("program") == "crimsonland.exe" and row.get("name")
    }

    assert signatures_by_name["effect_init_entry"] == (
        "void effect_init_entry(effect_entry_t *entry)"
    )
    assert signatures_by_name["effect_spawn"] == (
        "effect_entry_t * effect_spawn("
        "int effect_id, const vec2f_t *pos)"
    )
    assert signatures_by_name["creature_spawn_template"] == (
        "creature_t * creature_spawn_template("
        "int template_id, const vec2f_t *pos, float heading)"
    )
    assert signatures_by_name["creature_spawn_tinted"] == (
        "int creature_spawn_tinted("
        "const vec2f_t *pos, const effect_color_t *color, int type_id)"
    )
    assert signatures_by_name["creature_apply_damage"] == (
        "int creature_apply_damage("
        "int creature_id, float damage, int damage_type, "
        "const vec2f_t *impulse)"
    )
    assert signatures_by_name["player_fire_weapon"] == (
        "void player_fire_weapon("
        "const vec2f_t *aim, char fire_requested, char reload_requested)"
    )
    assert signatures_by_name["bonus_meta_entry_release"] == (
        "void __thiscall bonus_meta_entry_release(bonus_meta_cpp_t *entry)"
    )
    assert signatures_by_name["vec2_sub"] == (
        "float * __thiscall vec2_sub("
        "vec2f_t *self, float *dst, const vec2f_t *rhs)"
    )
    assert signatures_by_name["vec2_add"] == (
        "int vec2_add(vec2f_t *dst, const vec2f_t *delta)"
    )
    assert signatures_by_name["vec2_add_out"] == (
        "float * __thiscall vec2_add_out("
        "vec2f_t *self, float *dst, const vec2f_t *rhs)"
    )
    assert signatures_by_name["vec2_normalize_dispatch"] == (
        "vec2f_t * __stdcall vec2_normalize_dispatch("
        "vec2f_t *dst, const vec2f_t *src)"
    )
    assert signatures_by_name["wav_parse_into_entry"] == (
        "unsigned char wav_parse_into_entry("
        "sfx_entry_t *entry, void *data, unsigned int size)"
    )


def test_name_map_preserves_creature_death_pointer_local():
    map_path = (
        Path(__file__).parents[1]
        / "analysis"
        / "ghidra"
        / "maps"
        / "name_map.json"
    )
    rows = json.loads(map_path.read_text())
    death_row = next(
        row
        for row in rows
        if row.get("program") == "crimsonland.exe"
        and row.get("name") == "creature_handle_death"
    )

    assert death_row["local_types"] == [
        {
            "address": "0x0041e91d",
            "name": "creature",
            "type": "creature_t *",
        },
    ]


def test_name_map_preserves_quest_spawn_cursor_local_views():
    map_path = (
        Path(__file__).parents[1]
        / "analysis"
        / "ghidra"
        / "maps"
        / "name_map.json"
    )
    rows = json.loads(map_path.read_text())
    rows_by_name = {
        row["name"]: row
        for row in rows
        if row.get("program") == "crimsonland.exe" and row.get("name")
    }

    assert rows_by_name["quest_build_alien_squads"]["local_types"] == [
        {
            "address": "0x00436037",
            "name": "spawn_pair",
            "type": "quest_spawn_pair_binja_t *",
        },
    ]
    assert rows_by_name["quest_build_8_legged_terror"]["local_types"] == [
        {
            "address": "0x0043615f",
            "name": "spawn_pairs",
            "type": "quest_spawn_pair_binja_t *",
        },
        {
            "address": "0x004361aa",
            "name": "second_pair",
            "type": "quest_spawn_pair_binja_t *",
        },
    ]
    assert rows_by_name["quest_build_frontline_assault"]["local_types"] == [
        {
            "address": "0x00437eea",
            "name": "center_left_spawn",
            "type": "quest_spawn_entry_t *",
        },
    ]
    nagolipoli_types = rows_by_name["quest_build_nagolipoli"]["local_types"]
    assert nagolipoli_types[:4] == [
        {
            "address": "0x004345aa",
            "name": "corner_spawn_cursor",
            "type": "quest_spawn_entry_t *",
        },
        {
            "address": "0x004345e4",
            "name": "corner_spawn_second",
            "type": "quest_spawn_entry_t *",
        },
        {
            "address": "0x00434605",
            "name": "corner_spawn_third",
            "type": "quest_spawn_entry_t *",
        },
        {
            "address": "0x00434627",
            "name": "corner_spawn_fourth",
            "type": "quest_spawn_entry_t *",
        },
    ]


def test_name_map_preserves_ui_alpha_cursor_local_views():
    map_path = (
        Path(__file__).parents[1]
        / "analysis"
        / "ghidra"
        / "maps"
        / "name_map.json"
    )
    rows = json.loads(map_path.read_text())
    render_row = next(
        row
        for row in rows
        if row.get("program") == "crimsonland.exe"
        and row.get("name") == "ui_element_render"
    )

    assert render_row["local_types"] == [
        {
            "address": "0x00446d2c",
            "name": "static_alpha_cursor",
            "type": "ui_element_vertex_alpha_cursor_t *",
        },
        {
            "address": "0x00446d42",
            "name": "hover_alpha_cursor",
            "type": "ui_element_vertex_alpha_cursor_t *",
        },
    ]


def test_data_map_preserves_tutorial_bonus_carrier_overlay():
    map_path = (
        Path(__file__).parents[1]
        / "analysis"
        / "ghidra"
        / "maps"
        / "data_map.json"
    )
    rows = json.loads(map_path.read_text())["entries"]
    carrier_row = next(
        row
        for row in rows
        if row.get("program") == "crimsonland.exe"
        and row.get("name") == "tutorial_hint_bonus_ptr"
    )

    assert carrier_row["type"] == "tutorial_bonus_carrier_binja_t *"


def test_data_map_uses_flat_plugin_interface_presentation():
    map_path = (
        Path(__file__).parents[1]
        / "analysis"
        / "ghidra"
        / "maps"
        / "data_map.json"
    )
    rows = json.loads(map_path.read_text())["entries"]
    interface_row = next(
        row
        for row in rows
        if row.get("program") == "crimsonland.exe"
        and row.get("name") == "plugin_interface_ptr"
    )

    assert interface_row["type"] == "mod_interface_binja_t *"
