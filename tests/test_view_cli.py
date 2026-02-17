from __future__ import annotations

import os
from types import SimpleNamespace

from typer.testing import CliRunner

from crimson.cli import app


def test_view_autotune_requires_lighting_debug() -> None:
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "view",
            "empty",
            "--autotune-shadow-defaults",
        ],
    )

    assert result.exit_code == 1
    assert "--autotune-shadow-defaults is only supported for view 'lighting-debug'" in result.output


def test_view_autotune_and_dump_flags_are_mutually_exclusive() -> None:
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "view",
            "lighting-debug",
            "--autotune-shadow-defaults",
            "--dump-shader-debug-views",
        ],
    )

    assert result.exit_code == 1
    assert "--dump-shader-debug-views and --autotune-shadow-defaults cannot be used together" in result.output


def test_view_autotune_sets_env_and_invokes_run_view(monkeypatch) -> None:
    captured: dict[str, object] = {}
    view_def = SimpleNamespace(
        name="lighting-debug",
        title="Lighting Debug",
        factory=lambda ctx: SimpleNamespace(),
    )

    monkeypatch.setattr("crimson.views.view_by_name", lambda name: view_def if name == "lighting-debug" else None)
    monkeypatch.setattr("crimson.views.all_views", lambda: [view_def])

    def _fake_run_view(view, *, width, height, title, fps):
        captured["view"] = view
        captured["width"] = width
        captured["height"] = height
        captured["title"] = title
        captured["fps"] = fps

    monkeypatch.setattr("grim.app.run_view", _fake_run_view)
    os.environ.pop("CRIMSON_LIGHTING_DEBUG_AUTO_TUNE", None)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "view",
            "lighting-debug",
            "--autotune-shadow-defaults",
            "--autotune-shadow-frames",
            "55",
            "--width",
            "900",
            "--height",
            "600",
            "--fps",
            "75",
        ],
    )

    assert result.exit_code == 0, result.output
    assert os.environ.get("CRIMSON_LIGHTING_DEBUG_AUTO_TUNE") == "55"
    assert captured["width"] == 900
    assert captured["height"] == 600
    assert captured["fps"] == 75
    assert str(captured["title"]).startswith("Lighting Debug")
    os.environ.pop("CRIMSON_LIGHTING_DEBUG_AUTO_TUNE", None)
