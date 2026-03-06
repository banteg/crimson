from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from crimson.debug_views import _runtime_resources as runtime_resources
from crimson.debug_views import spawn_plan
from grim.view import ViewContext

ASSETS_DIR = Path("artifacts/assets")


class _MixinHarness(runtime_resources.RuntimeResourcesDebugViewMixin):
    def __init__(self) -> None:
        self._assets_root = ASSETS_DIR


def test_open_runtime_resources_loads_when_missing(mocker) -> None:
    mocker.patch.object(runtime_resources, "runtime_resources_for", side_effect=RuntimeError("missing"))
    load_runtime_resources = mocker.patch.object(runtime_resources, "load_runtime_resources")
    view = _MixinHarness()

    view._open_runtime_resources()

    assert view._runtime_resources_owned is True
    load_runtime_resources.assert_called_once_with(ASSETS_DIR)


def test_open_runtime_resources_reuses_registered_assets(mocker) -> None:
    runtime_lookup = mocker.patch.object(runtime_resources, "runtime_resources_for", return_value=object())
    load_runtime_resources = mocker.patch.object(runtime_resources, "load_runtime_resources")
    view = _MixinHarness()

    view._open_runtime_resources()

    assert view._runtime_resources_owned is False
    runtime_lookup.assert_called_once_with(ASSETS_DIR)
    load_runtime_resources.assert_not_called()


def test_close_runtime_resources_unloads_owned_assets(mocker) -> None:
    resources = object()
    runtime_lookup = mocker.patch.object(runtime_resources, "runtime_resources_for", return_value=resources)
    unload_runtime_resources = mocker.patch.object(runtime_resources, "unload_runtime_resources")
    view = _MixinHarness()
    view._runtime_resources_owned = True

    view._close_runtime_resources()

    runtime_lookup.assert_called_once_with(ASSETS_DIR)
    unload_runtime_resources.assert_called_once_with(resources)
    assert view._runtime_resources_owned is False


def test_spawn_plan_view_owns_runtime_resources_when_opened_directly(mocker) -> None:
    open_runtime_resources = mocker.patch.object(spawn_plan.SpawnPlanView, "_open_runtime_resources")
    close_runtime_resources = mocker.patch.object(spawn_plan.SpawnPlanView, "_close_runtime_resources")
    load_small_font = mocker.patch.object(spawn_plan, "load_small_font", return_value=SimpleNamespace(cell_size=8))

    view = spawn_plan.SpawnPlanView(ViewContext(assets_dir=ASSETS_DIR))
    view.open()
    view.close()

    open_runtime_resources.assert_called_once_with()
    load_small_font.assert_called_once_with(ASSETS_DIR)
    close_runtime_resources.assert_called_once_with()
