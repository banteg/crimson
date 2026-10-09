from __future__ import annotations

import importlib.util
import json
from enum import Enum
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

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


def test_resolve_creates_bounded_overlap_without_removing_owner(monkeypatch):
    importer = _load_importer()
    containing = SimpleNamespace(start=0x3000)
    view = _FakeView([containing], prefix=b"\x55\x8b\xec")
    monkeypatch.setattr(importer, "_is_direct_jump_wrapper", lambda _bv, _func, _addr: False)

    func, created = importer._resolve_function_for_name_row(
        view,
        {"name": "archive_entry", "end": "0x3040"},
        0x3030,
    )

    assert created is True
    assert func.start == 0x3030
    assert view.created == [0x3030]
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


def test_name_map_typed_rows_are_function_declarations():
    importer = _load_importer()
    map_path = (
        Path(__file__).parents[1]
        / "analysis"
        / "ghidra"
        / "maps"
        / "name_map.json"
    )
    rows = json.loads(map_path.read_text(encoding="utf-8"))

    invalid = [
        row["name"]
        for row in rows
        if row.get("signature")
        and not importer._is_function_declaration(str(row["signature"]))
    ]

    assert invalid == []


@pytest.mark.parametrize(
    ("declaration", "expected"),
    [
        ("void archive_entry(void)", True),
        ("void (*callback)(void)", False),
    ],
)
def test_function_declaration_classifier(declaration, expected):
    importer = _load_importer()

    assert importer._is_function_declaration(declaration) is expected


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


def test_written_variable_at_rejects_unavailable_mlil():
    importer = _load_importer()
    function = SimpleNamespace(mlil=None)

    with pytest.raises(LookupError, match="MLIL unavailable"):
        importer._written_variable_at(function, 0x4502F1)


def test_written_variable_at_prefers_confirmed_available_mlil():
    importer = _load_importer()
    variable = object()
    instruction = SimpleNamespace(
        address=0x4502F1,
        vars_written=[SimpleNamespace(var=variable)],
    )
    function = SimpleNamespace(
        mlil=None,
        mlil_if_available=SimpleNamespace(ssa_form=[[instruction]]),
    )

    assert importer._written_variable_at(function, 0x4502F1) is variable


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
        frozenset({"i_4", "creature_death_timer_cursor"}),
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
            self.mlil_if_available = None
            self._advanced_analysis_requests = 0
            self.reanalysis_count = 0

        def request_advanced_analysis_data(self):
            self._advanced_analysis_requests += 1
            self.llil_if_available = object()
            self.mlil_if_available = object()

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

    assert count == 0
    assert function.created == []


def test_apply_function_local_types_uses_captured_mlil(monkeypatch):
    importer = _load_importer()
    local_type = object()
    variable = SimpleNamespace(name="temporary", type=object())
    captured_mlil = SimpleNamespace(
        ssa_form=[
            [
                SimpleNamespace(
                    address=0x4502F1,
                    vars_written=[SimpleNamespace(var=variable)],
                ),
            ],
        ],
    )

    class FakeFunction:
        mlil = None
        mlil_if_available = None

        def __init__(self):
            self.created = []

        def is_var_user_defined(self, _var):
            return False

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
        captured_mlil,
    )

    assert count == 1
    assert function.created == [
        (variable, local_type, "menu_item_vertex0_element"),
    ]


def test_function_signature_replay_is_idempotent(monkeypatch):
    importer = _load_importer()
    function_type = object()

    class FakeFunction:
        type = function_type

        def __init__(self):
            self.applied = []

        def set_user_type(self, type_obj):
            self.applied.append(type_obj)

    function = FakeFunction()
    monkeypatch.setattr(importer, "_seed_common_types", lambda _bv: None)
    monkeypatch.setattr(
        importer,
        "_sanitize_signature",
        lambda signature, _bv: signature,
    )
    monkeypatch.setattr(
        importer,
        "_parse_type_string",
        lambda _bv, _signature: function_type,
    )

    assert not importer._apply_function_signature(
        object(),
        function,
        "void recovered(void)",
    )
    assert function.applied == []


def test_function_type_parser_reuses_equivalent_named_declarations(monkeypatch):
    importer = _load_importer()
    function_type = object()
    view = object()
    parse_type = Mock(return_value=function_type)
    monkeypatch.setattr(importer, "_seed_common_types", lambda _bv: None)
    monkeypatch.setattr(
        importer,
        "_sanitize_signature",
        lambda signature, _bv: signature,
    )
    monkeypatch.setattr(importer, "_parse_type_string", parse_type)
    cache = {}

    assert importer._resolve_function_type(
        view,
        "void first(int value)",
        cache,
    ) is function_type
    assert importer._resolve_function_type(
        view,
        "void second(int value)",
        cache,
    ) is function_type
    parse_type.assert_called_once_with(view, "void first(int value)")
