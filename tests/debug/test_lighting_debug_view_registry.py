from __future__ import annotations

from pathlib import Path

from grim.view import ViewContext


def test_import_crimson_views_succeeds() -> None:
    import crimson.debug_views as views

    assert views is not None


def test_lighting_debug_view_is_registered() -> None:
    from crimson.debug_views import all_views, view_by_name

    entry = view_by_name("lighting-debug")
    assert entry is not None
    assert "lighting-debug" in {view.name for view in all_views()}


def test_lighting_debug_factory_constructs_without_window() -> None:
    from crimson.debug_views import view_by_name
    from crimson.debug_views.lighting_debug import LightingDebugView

    entry = view_by_name("lighting-debug")
    assert entry is not None

    ctx = ViewContext(assets_dir=Path(".") / "artifacts" / "assets")
    instance = entry.factory(ctx)
    view = instance.view
    assert isinstance(view, LightingDebugView)
    assert view._auto_emit_enabled is False

    assert not instance.hooks.should_close()
    view.close_requested = True
    assert instance.hooks.should_close()
