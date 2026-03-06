from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from crimson.debug_views import _runtime_resources as runtime_resources
from crimson.debug_views import spawn_plan
from grim.view import ViewContext

ASSETS_DIR = Path("artifacts/assets")


def test_ensure_runtime_resources_loaded_loads_when_missing(mocker) -> None:
    mocker.patch.object(runtime_resources, "runtime_resources_for", side_effect=RuntimeError("missing"))
    load_runtime_resources = mocker.patch.object(runtime_resources, "load_runtime_resources")

    owned = runtime_resources.ensure_runtime_resources_loaded(ASSETS_DIR)

    assert owned is True
    load_runtime_resources.assert_called_once_with(ASSETS_DIR)


def test_ensure_runtime_resources_loaded_reuses_registered_assets(mocker) -> None:
    runtime_lookup = mocker.patch.object(runtime_resources, "runtime_resources_for", return_value=object())
    load_runtime_resources = mocker.patch.object(runtime_resources, "load_runtime_resources")

    owned = runtime_resources.ensure_runtime_resources_loaded(ASSETS_DIR)

    assert owned is False
    runtime_lookup.assert_called_once_with(ASSETS_DIR)
    load_runtime_resources.assert_not_called()


def test_release_runtime_resources_unloads_owned_assets(mocker) -> None:
    resources = object()
    runtime_lookup = mocker.patch.object(runtime_resources, "runtime_resources_for", return_value=resources)
    unload_runtime_resources = mocker.patch.object(runtime_resources, "unload_runtime_resources")

    runtime_resources.release_runtime_resources(ASSETS_DIR, owned=True)

    runtime_lookup.assert_called_once_with(ASSETS_DIR)
    unload_runtime_resources.assert_called_once_with(resources)


def test_spawn_plan_view_owns_runtime_resources_when_opened_directly(mocker) -> None:
    ensure_runtime_resources_loaded = mocker.patch.object(
        spawn_plan,
        "ensure_runtime_resources_loaded",
        return_value=True,
    )
    release_runtime_resources = mocker.patch.object(spawn_plan, "release_runtime_resources")
    load_small_font = mocker.patch.object(spawn_plan, "load_small_font", return_value=SimpleNamespace(cell_size=8))

    view = spawn_plan.SpawnPlanView(ViewContext(assets_dir=ASSETS_DIR))
    view.open()
    view.close()

    ensure_runtime_resources_loaded.assert_called_once_with(ASSETS_DIR)
    load_small_font.assert_called_once_with(ASSETS_DIR)
    release_runtime_resources.assert_called_once_with(ASSETS_DIR, owned=True)
