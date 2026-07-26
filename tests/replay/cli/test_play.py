from __future__ import annotations

from typer.testing import CliRunner

from crimson import runtime_resources_view
from crimson.cli import app
from crimson.game_modes import GameMode
from tests.replay.cli._helpers import build_replay, write_replay


def test_replay_play_owns_runtime_resources_at_cli_boundary(tmp_path, mocker) -> None:
    import grim.app as grim_app
    from crimson import assets_fetch
    from crimson.modes import replay_playback_mode

    replay = build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    mocker.patch.object(assets_fetch, "download_missing_paqs")
    load_runtime_resources = mocker.patch.object(runtime_resources_view, "load_runtime_resources", return_value=object())
    unload_runtime_resources = mocker.patch.object(runtime_resources_view, "unload_runtime_resources")
    inner_open = mocker.patch.object(replay_playback_mode.ReplayPlaybackMode, "open")
    inner_close = mocker.patch.object(replay_playback_mode.ReplayPlaybackMode, "close")
    run_view = mocker.patch.object(grim_app, "run_view")

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "replay",
            "play",
            str(replay_path),
            "--base-dir",
            str(tmp_path),
            "--assets-dir",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0, result.output
    run_view.assert_called_once()
    wrapped_view = run_view.call_args.args[0]
    wrapped_view.open()
    load_runtime_resources.assert_called_once()
    inner_open.assert_called_once()
    wrapped_view.close()
    inner_close.assert_called_once()
    unload_runtime_resources.assert_called_once()
