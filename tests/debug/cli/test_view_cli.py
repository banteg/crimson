from __future__ import annotations

import os
from types import SimpleNamespace

from typer.testing import CliRunner

import crimson.debug_views as views
import grim.app as grim_app
from crimson.cli import app
from crimson.debug_views.registry import ViewInstance
from tests.support.screens import ScreenStub


def test_view_autotune_requires_lighting_debug() -> None:
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "view",
            "arsenal",
            "--autotune-shadow-defaults",
        ],
    )

    assert result.exit_code == 1
    assert "--autotune-shadow-defaults is only supported for view 'lighting-debug'" in result.output


def test_view_autotune_and_dump_flags_are_mutually_exclusive(mocker) -> None:
    view_def = SimpleNamespace(
        name="lighting-debug",
        title="Lighting Debug",
        factory=lambda ctx: ViewInstance(ScreenStub()),
    )
    mocker.patch.object(views, "view_by_name", side_effect=lambda name: view_def if name == "lighting-debug" else None)
    mocker.patch.object(views, "all_views", side_effect=lambda: [view_def])

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


def test_view_autotune_sets_env_and_invokes_run_view(mocker) -> None:
    view_def = SimpleNamespace(
        name="lighting-debug",
        title="Lighting Debug",
        factory=lambda ctx: ViewInstance(ScreenStub()),
    )

    mocker.patch.object(views, "view_by_name", side_effect=lambda name: view_def if name == "lighting-debug" else None)
    mocker.patch.object(views, "all_views", side_effect=lambda: [view_def])

    run_view = mocker.patch.object(grim_app, "run_view")
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
    run_view.assert_called_once()
    kwargs = run_view.call_args.kwargs
    assert os.environ.get("CRIMSON_LIGHTING_DEBUG_AUTO_TUNE") == "55"
    assert kwargs["width"] == 900
    assert kwargs["height"] == 600
    assert kwargs["fps"] == 75
    assert str(kwargs["title"]).startswith("Lighting Debug")
    os.environ.pop("CRIMSON_LIGHTING_DEBUG_AUTO_TUNE", None)
