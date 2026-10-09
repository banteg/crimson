from __future__ import annotations

from typer.testing import CliRunner

from crimson.cli.app import app


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
