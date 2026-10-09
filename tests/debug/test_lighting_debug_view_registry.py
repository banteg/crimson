from __future__ import annotations

from pathlib import Path

from grim.view import ViewContext


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
