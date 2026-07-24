from __future__ import annotations

import importlib.util
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
    assert not importer._should_replace_repo_type(
        "unrelated_complete_type",
        object(),
        object(),
    )
