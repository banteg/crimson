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
        "quest_spawn_entries_binja_t",
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
