from __future__ import annotations

import importlib.util
import json
from enum import Enum
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


def test_resolve_splits_padding_prefixed_function_without_create_flag(monkeypatch):
    importer = _load_importer()
    padding_function = SimpleNamespace(start=0x2000)
    view = _FakeView([padding_function], prefix=b"\x90" * 8)
    monkeypatch.setattr(importer, "_is_direct_jump_wrapper", lambda _bv, _func, _addr: False)

    func, created = importer._resolve_function_for_name_row(
        view,
        {"name": "empty_destructor"},
        0x2008,
    )

    assert created is True
    assert func.start == 0x2008
    assert view.removed == [padding_function]
    assert view.created == [0x2008]


def test_resolve_rejects_non_padding_interior_function_without_create_flag(monkeypatch):
    importer = _load_importer()
    containing = SimpleNamespace(start=0x3000)
    view = _FakeView([containing], prefix=b"\x55\x8b\xec")
    monkeypatch.setattr(importer, "_is_direct_jump_wrapper", lambda _bv, _func, _addr: False)

    with pytest.raises(RuntimeError, match="inside an existing function"):
        importer._resolve_function_for_name_row(
            view,
            {"name": "interior"},
            0x3003,
        )

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
        "creature_lifecycle_stride_binja_t",
        object(),
        object(),
    )
    assert importer._should_replace_repo_type(
        "creature_max_health_stride_binja_t",
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
        "game_status_binja_t",
        object(),
        object(),
    )
    assert importer._should_replace_repo_type(
        "highscore_record_t",
        object(),
        object(),
    )
    assert importer._should_replace_repo_type(
        "player_input_config_t",
        object(),
        object(),
    )
    assert importer._should_replace_repo_type(
        "crimson_cfg_t",
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
        "quest_spawn_entry_template_cursor_t",
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
    assert importer._REPO_TYPE_VIEW_OVERRIDES["game_status_t"] == (
        "game_status_binja_t"
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


def test_data_map_preserves_recovered_aggregate_alias_types():
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

    assert types_by_name["config_direction_arrow_flags"] == "unsigned char[2]"
    assert types_by_name["config_player_mode_flags"] == "int[4]"
    assert types_by_name["config_aim_scheme"] == "int[4]"
    assert types_by_name["config_player_name_buf"] == "char[12]"
    assert types_by_name["config_saved_name_order"] == "int[8]"
    assert types_by_name["config_saved_name_7"] == "char[27]"
    assert types_by_name["config_player_name"] == "char[32]"
    assert types_by_name["config_p2_axis_move_x"] == "int"
    assert (
        types_by_name["console_command_list_head"]
        == "console_command_entry_t *"
    )
    assert types_by_name["console_log_head"] == "console_log_node_t *"
    assert types_by_name["credits_secret_match_mask_v1"] == "int"
    assert types_by_name["game_sequence_id"] == "unsigned int"
    assert types_by_name["highscore_score_xp"] == "unsigned int"
    assert types_by_name["highscore_record_weapon_id"] == "unsigned char"
    assert types_by_name["quest_selected_builder"] == "quest_builder_fn_t"
    assert types_by_name["player_perk_counts"] == "int[128]"
    assert types_by_name["player2_health"] == "float"
    assert types_by_name["player_aim_screen_y"] == "float"
    assert types_by_name["creature_orbit_radius"] == "creature_orbit_radius_t"
    assert types_by_name["creature_type_trooper"] == "creature_type_t"
    assert types_by_name["creature_spawn_slot_timer"] == "float"
    assert types_by_name["projectile_type_id"] == "projectile_type_id_t"
    assert (
        types_by_name["secondary_proj_type_id"]
        == "secondary_projectile_type_id_t"
    )
    assert types_by_name["secondary_proj_lifetime"] == "float"
    assert types_by_name["effect_pool_effect_id"] == "unsigned char"
    assert types_by_name["effect_pool_quad_data"] == "effect_vertex_t[4]"
    assert types_by_name["particle_style_id"] == "unsigned char"
    assert types_by_name["bonus_label_points"] == "char *"
    assert types_by_name["bonus_hud_slot_timer_ptr"] == "float *"
    assert types_by_name["bonus_hud_slot_y"] == "float"
    assert types_by_name["perk_desc_table"] == "char *"
    assert types_by_name["perk_flags_table"] == "int"
    assert types_by_name["weapon_projectile_travel_budget"] == "float"
    assert types_by_name["ui_sign_crimson_update_disabled"] == "unsigned char"
    assert types_by_name["perk_prompt_transform_cos"] == "float"
    assert (
        types_by_name["ui_menu_item_subtemplate_block_01_texture_handle"]
        == "int"
    )
    assert types_by_name["ui_menu_item_subtemplate_block_06_mode"] == "int"
    assert types_by_name["local_system_milliseconds"] == "unsigned short"
    assert types_by_name["sfx_entry_table_state"] == "void *"
    assert types_by_name["controls_key_reload_item"] == "ui_menu_item_t"
    assert types_by_name["effect_uv16_v"] == "float"


def test_data_map_preserves_recovered_standalone_semantic_types():
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

    expected = {
        "aim_screen_x": "float",
        "aim_screen_y": "float",
        "game_completed_screen_flags": "char",
        "credits_secret_button": "ui_button_t",
        "credits_secret_button_clicked": "unsigned char",
        "credits_back_button": "ui_button_t",
        "credits_back_button_clicked": "unsigned char",
        "sfx_trooper_inpain_02": "int",
        "sfx_trooper_inpain_03": "int",
        "sfx_bullet_hit_02": "int",
        "sfx_bullet_hit_03": "int",
        "sfx_bullet_hit_04": "int",
        "sfx_bullet_hit_05": "int",
        "sfx_bullet_hit_06": "int",
        "sfx_trooper_inpain_01_alias_0": "int",
        "sfx_trooper_inpain_01_alias_2": "int",
        "sfx_ui_typeclick_02": "int",
        "sfx_bloodspill_02": "int",
    }

    assert {name: types_by_name[name] for name in expected} == expected


def test_data_map_preserves_recovered_crt_and_weapon_alias_types():
    map_path = (
        Path(__file__).parents[1]
        / "analysis"
        / "ghidra"
        / "maps"
        / "data_map.json"
    )
    rows = json.loads(map_path.read_text())["entries"]
    by_address = {
        row["address"]: row
        for row in rows
        if row.get("program") == "crimsonland.exe"
    }

    expected = {
        "0x0046fad8": ("crt_output_lookup_table", "unsigned char[92]"),
        "0x00471000": ("crt_xc_begin", "void *"),
        "0x004710e0": ("crt_xc_end", "void *"),
        "0x004710e4": ("crt_xi_begin", "void *"),
        "0x004710f8": ("crt_xi_end", "void *"),
        "0x0047b160": ("crt_fp_init_hook", "void *"),
        "0x0047b1a8": ("crt_cfltcvt_table", "void *[6]"),
        "0x0047b1c0": ("crt_ctype_table", "unsigned short *"),
        "0x0047b1c8": ("crt_ctype_data", "unsigned short[258]"),
        "0x0047b3d8": ("crt_iob", "unsigned char[640]"),
        "0x0047b658": ("crt_null_string", "char *"),
        "0x0047b65c": ("crt_wide_null_string", "wchar_t *"),
        "0x0047b7c0": (
            "crt_dosmaperr_table",
            "crt_dosmaperr_entry_t[45]",
        ),
        "0x0047b928": ("crt_inconsistency_handler", "void *"),
        "0x0047b930": ("crt_bad_ioinfo", "crt_ioinfo_t"),
        "0x0047db18": ("crt_scan_bracket_set", "char[6]"),
        "0x0047db20": ("crt_scan_closing_bracket_set", "char[2]"),
        "0x0047db28": (
            "crt_runtime_errors",
            "crt_runtime_error_entry_t[18]",
        ),
        "0x0047dcb8": ("crt_x87_overflow_value", "unsigned char[10]"),
        "0x0047dcc4": ("crt_x87_underflow_value", "unsigned char[10]"),
        "0x0047defc": ("crt_tz_names", "char *[2]"),
        "0x0047df08": ("crt_dst_start_rule", "int[3]"),
        "0x0047df18": ("crt_dst_end_rule", "int[3]"),
        "0x0047df24": ("crt_leap_year_days", "int[13]"),
        "0x0047df58": ("crt_month_days", "int[13]"),
        "0x0047df90": ("crt_codepage_ctype_flags", "unsigned char[4]"),
        "0x0047df98": ("crt_codepage_info", "crt_codepage_info_t[5]"),
        "0x004d7a90": ("weapon_hud_icon_id", "int"),
        "0x004d9970": ("crt_gmt_cache", "SYSTEMTIME"),
        "0x004d9980": ("crt_umask", "int"),
        "0x004d9984": ("crt_os_version", "unsigned int"),
        "0x004d9988": ("crt_windows_version", "unsigned int"),
        "0x004d998c": ("crt_windows_major", "unsigned int"),
        "0x004d9990": ("crt_windows_minor", "unsigned int"),
        "0x004d9b98": ("crt_timezone_info", "unsigned char[172]"),
        "0x004da3a8": ("crt_heap_mode", "int"),
        "0x004db4f0": ("crt_onexit_table_end", "crt_onexit_fn_t *"),
        "0x004db4f4": ("crt_onexit_table_begin", "crt_onexit_fn_t *"),
    }

    assert {
        address: (by_address[address]["name"], by_address[address].get("type"))
        for address in expected
    } == expected


def test_data_map_classifies_instruction_annotations_as_code_labels():
    map_path = (
        Path(__file__).parents[1]
        / "analysis"
        / "ghidra"
        / "maps"
        / "data_map.json"
    )
    rows = json.loads(map_path.read_text())["entries"]

    assert {
        row["name"]
        for row in rows
        if row.get("program") == "crimsonland.exe"
        and row.get("kind") == "code_label"
    } == {
        "game_startup_intro_mute_callsite",
        "game_startup_theme_play_callsite",
        "game_startup_intro_play_callsite",
        "crt_strstr_to_strchr",
        "crt_se_translator_return_point",
        "crt_se_translator_exception_continuation",
    }


def test_data_map_symbol_type_distinguishes_data_and_code_labels(monkeypatch):
    importer = _load_importer()
    symbol_types = SimpleNamespace(DataSymbol=object(), LocalLabelSymbol=object())
    monkeypatch.setattr(
        importer,
        "bn",
        SimpleNamespace(SymbolType=symbol_types),
    )

    assert importer._data_map_symbol_type({}) is symbol_types.DataSymbol
    assert (
        importer._data_map_symbol_type({"kind": "code_label"})
        is symbol_types.LocalLabelSymbol
    )
    with pytest.raises(ValueError, match="unsupported data-map entry kind"):
        importer._data_map_symbol_type({"kind": "function"})


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


def test_written_variable_at_uses_source_name_for_ambiguous_address():
    importer = _load_importer()
    induction_cursor = SimpleNamespace(name="i_4")
    unrelated_phi = SimpleNamespace(name="i_3")
    instruction = SimpleNamespace(
        address=0x40573E,
        vars_written=[
            SimpleNamespace(var=unrelated_phi),
            SimpleNamespace(var=induction_cursor),
        ],
    )
    function = SimpleNamespace(
        mlil=SimpleNamespace(ssa_form=[[instruction]]),
    )

    assert importer._written_variable_at(
        function,
        0x40573E,
        frozenset({"i_4", "creature_lifecycle_cursor"}),
    ) is induction_cursor


def test_analysis_skip_override_is_idempotent():
    importer = _load_importer()

    class AnalysisOverride(Enum):
        DefaultFunctionAnalysis = 0
        NeverSkipFunctionAnalysis = 1

    class FakeFunction:
        def __init__(self):
            self.analysis_skip_override = (
                AnalysisOverride.DefaultFunctionAnalysis
            )
            self.llil_if_available = None
            self._advanced_analysis_requests = 0
            self.reanalysis_count = 0

        def request_advanced_analysis_data(self):
            self._advanced_analysis_requests += 1
            self.llil_if_available = object()

        def reanalyze(self):
            self.reanalysis_count += 1

    function = FakeFunction()

    assert importer._apply_analysis_skip_override(
        function,
        "never_skip",
    )
    assert function.reanalysis_count == 1
    assert function._advanced_analysis_requests == 1
    assert (
        function.analysis_skip_override
        == AnalysisOverride.NeverSkipFunctionAnalysis
    )
    assert not importer._apply_analysis_skip_override(
        function,
        "never_skip",
    )
    assert function.reanalysis_count == 1
    assert function._advanced_analysis_requests == 1


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
    assert signatures_by_name["creature_render_type"] == (
        "void creature_render_type(int type_id, float transition_alpha)"
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
    assert signatures_by_name["ui_render_loading"] == (
        "void ui_render_loading(void)"
    )
    assert signatures_by_name["credits_secret_match3_find"] == (
        "unsigned char credits_secret_match3_find("
        "int *board, int *out_idx, unsigned char *out_dir)"
    )
    assert signatures_by_name["ui_element_set_rect"] == (
        "void ui_element_set_rect("
        "ui_menu_item_subtemplate_block_t *element, "
        "float width, float height, float *offset)"
    )
    assert signatures_by_name["highscore_compare_survival_score_desc"] == (
        "int highscore_compare_survival_score_desc("
        "const highscore_record_t *a, const highscore_record_t *b)"
    )
    assert signatures_by_name["highscore_compare_rush_field32_desc"] == (
        "int highscore_compare_rush_field32_desc("
        "const highscore_record_t *a, const highscore_record_t *b)"
    )
    assert signatures_by_name[
        "highscore_compare_quest_field32_asc_nonzero_first"
    ] == (
        "int highscore_compare_quest_field32_asc_nonzero_first("
        "const highscore_record_t *a, const highscore_record_t *b)"
    )


def test_name_map_preserves_gameplay_analysis_and_cursor_recovery():
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
    never_skip = {
        name
        for name, row in rows_by_name.items()
        if row.get("analysis_skip_override") == "never_skip"
    }

    assert {
        "perk_apply",
        "perks_update_effects",
        "survival_spawn_creature",
        "camera_update",
        "gameplay_run_state_init",
        "bonus_pool_global_init",
        "game_status_global_init",
        "highscore_init_sentinels",
        "bonus_pick_random_type",
        "player_start_reload",
        "player_heading_approach_target",
        "player_update",
        "projectile_update",
        "creature_update_all",
        "creature_spawn_template",
        "terrain_generate",
        "creature_render_type",
        "creature_render_all",
        "projectile_render",
        "ui_render_loading",
        "input_key_name",
        "tutorial_prompt_dialog",
        "credits_secret_match3_find",
        "game_mode_label",
        "ui_draw_textured_quad",
        "terrain_render",
        "ui_element_set_rect",
        "ui_cursor_render",
        "ui_render_aim_enhancement",
        "ui_draw_progress_bar",
        "bonus_hud_slot_activate",
        "highscore_screen_update",
        "controls_menu_update",
    } <= never_skip
    assert rows_by_name["projectile_update"]["local_types"] == [
        {
            "address": "0x00421a0d",
            "name": "secondary_vel_y_cursor",
            "type": "secondary_projectile_vel_y_block_t *",
        },
        {
            "address": "0x00421ab1",
            "name": "creature_pos_y_cursor",
            "type": "float *",
        },
        {
            "address": "0x004224f0",
            "name": "particle_vel_y_cursor",
            "type": "float *",
        },
    ]
    assert rows_by_name["perk_apply"]["local_types"][1] == {
        "address": "0x0040573e",
        "source_name": "i_4",
        "name": "creature_lifecycle_cursor",
        "type": "float *",
    }
    assert rows_by_name["bonus_update"]["local_types"] == [
        {
            "address": "0x0040a337",
            "name": "bonus_time_cursor",
            "type": "bonus_entry_time_block_t *",
        },
        {
            "address": "0x0040a346",
            "name": "bonus_entry",
            "type": "bonus_entry_t *",
        },
    ]
    assert rows_by_name["player_update"]["local_types"] == [
        {
            "address": "0x004136ed",
            "name": "player",
            "type": "player_state_t *",
        },
        {
            "address": "0x004136f6",
            "name": "player_position",
            "type": "vec2f_t *",
        },
    ]
    assert rows_by_name["creature_update_all"]["local_types"] == [
        {
            "address": "0x00426403",
            "name": "creature_position",
            "type": "vec2f_t *",
        },
        {
            "address": "0x0042646e",
            "name": "alternate_player_position",
            "type": "vec2f_t *",
        },
    ]
    assert rows_by_name["effects_update"]["local_types"] == [
        {
            "address": "0x0042e714",
            "name": "effect_age_cursor",
            "type": "float *",
        },
    ]
    assert rows_by_name["effects_render"]["local_types"] == [
        {
            "address": "0x0042e879",
            "name": "background_effect_color_g_cursor",
            "type": "float *",
        },
        {
            "address": "0x0042e9c3",
            "name": "foreground_effect_color_g_cursor",
            "type": "float *",
        },
    ]
    assert rows_by_name["terrain_generate"]["local_types"] == [
        {
            "address": "0x00417d11",
            "name": "base_quad_size",
            "type": "float",
        },
        {
            "address": "0x00417e78",
            "name": "detail_quad_size",
            "type": "float",
        },
        {
            "address": "0x00417fdb",
            "name": "accent_quad_size",
            "type": "float",
        },
    ]
    assert rows_by_name["creature_render_type"]["local_types"][:2] == [
        {
            "address": "0x00418c0a",
            "name": "detail_lifecycle_cursor",
            "type": "creature_lifecycle_stride_binja_t *",
        },
        {
            "address": "0x00418eb0",
            "name": "energizer_max_health_cursor",
            "type": "creature_max_health_stride_binja_t *",
        },
    ]
    assert rows_by_name["projectile_render"]["local_types"][1:4] == [
        {
            "address": "0x00423011",
            "name": "bullet_vel_y_cursor",
            "type": "projectile_vel_y_block_t *",
        },
        {
            "address": "0x004237e4",
            "name": "plasma_pos_y_cursor",
            "type": "projectile_pos_y_block_t *",
        },
        {
            "address": "0x00424184",
            "name": "projectile_origin_y_cursor",
            "type": "projectile_tail_t *",
        },
    ]
    assert rows_by_name["ui_element_set_rect"]["local_types"] == [
        {
            "address": "0x00419bdc",
            "name": "vertex_y_cursor",
            "type": "float *",
        },
    ]
    assert rows_by_name["controls_menu_update"]["local_types"] == [
        {
            "address": "0x004492a1",
            "name": "binding_axis_move_x_cursor",
            "type": "int *",
        },
    ]
    assert rows_by_name["highscore_screen_update"]["local_types"] == [
        {
            "address": "0x00442b63",
            "name": "score_count",
            "type": "int",
        },
        {
            "address": "0x00442b6b",
            "name": "score_line_item_cursor",
            "type": "char **",
        },
        {
            "address": "0x00442b76",
            "name": "record_flags_cursor",
            "type": "uint8_t *",
        },
        {
            "address": "0x00442b7b",
            "name": "score_line_buffer_cursor",
            "type": "char (*)[164]",
        },
        {
            "address": "0x00442b9a",
            "name": "prefix_length",
            "type": "int",
        },
        {
            "address": "0x00442bd6",
            "name": "record_name",
            "type": "char *",
        },
        {
            "address": "0x00442c04",
            "name": "record_name",
            "type": "char *",
        },
        {
            "address": "0x00442c33",
            "name": "record_name",
            "type": "char *",
        },
    ]


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

    assert rows_by_name["quest_spawn_timeline_update"]["local_types"] == [
        {
            "address": "0x004342d2",
            "name": "spawn_batch",
            "type": "quest_spawn_entries_binja_t *",
        },
    ]
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
    assert rows_by_name["quest_build_lizard_kings"]["local_types"] == [
        {
            "address": "0x00437799",
            "name": "angle_index",
            "type": "int",
        },
        {
            "address": "0x004377a2",
            "name": "ring_spawn_cursor",
            "type": "quest_spawn_entry_template_cursor_t *",
        },
    ]
    assert rows_by_name["quest_build_surrounded_by_reptiles"][
        "local_types"
    ] == [
        {
            "address": "0x004389c5",
            "name": "second_line_cursor",
            "type": "quest_spawn_entry_t *",
        },
    ]
    assert rows_by_name["quest_build_the_annihilation"]["local_types"] == [
        {
            "address": "0x004382ea",
            "name": "first_column_cursor",
            "type": "quest_spawn_entry_template_cursor_t *",
        },
        {
            "address": "0x00438364",
            "name": "second_column_cursor",
            "type": "quest_spawn_entry_template_cursor_t *",
        },
    ]
    template_cursor_sites = {
        "quest_build_monster_blues": [
            ("0x00434959", "random_wave_cursor"),
        ],
    }
    for name, sites in template_cursor_sites.items():
        assert rows_by_name[name]["local_types"] == [
            {
                "address": address,
                "name": cursor_name,
                "type": "quest_spawn_entry_template_cursor_t *",
            }
            for address, cursor_name in sites
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
