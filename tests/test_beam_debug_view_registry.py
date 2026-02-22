from __future__ import annotations

from pathlib import Path

from grim.view import ViewContext


def test_beam_debug_view_is_registered() -> None:
    from crimson.views import all_views, view_by_name

    entry = view_by_name("beam-debug")
    assert entry is not None
    assert "beam-debug" in {view.name for view in all_views()}


def test_beam_debug_factory_constructs_without_window() -> None:
    from crimson.views import view_by_name
    from crimson.views.beam_debug import BeamDebugView

    entry = view_by_name("beam-debug")
    assert entry is not None

    ctx = ViewContext(assets_dir=Path(".") / "artifacts" / "assets")
    view = entry.factory(ctx)
    assert isinstance(view, BeamDebugView)
    assert view.close_requested is False
