from __future__ import annotations

import msgspec
from typer.testing import CliRunner

import grim.audio as grim_audio
from crimson import runtime_resources_view
from crimson.cli.app import app
from crimson.game_modes import GameMode
from tests.replay.cli._helpers import build_replay, write_payload_bytes, write_replay


def test_replay_play_owns_runtime_resources_at_cli_boundary(tmp_path, mocker) -> None:
    import grim.app as grim_app
    from crimson import runtime_boot
    from crimson.modes import replay_playback_mode

    replay = build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = write_replay(tmp_path, replay=replay, name="survival.crd")

    mocker.patch.object(runtime_boot, "download_missing_paqs")
    load_runtime_resources = mocker.patch.object(runtime_resources_view, "load_runtime_resources", return_value=object())
    unload_runtime_resources = mocker.patch.object(runtime_resources_view, "unload_runtime_resources")
    mocker.patch.object(replay_playback_mode, "open_replay_audio", return_value=object())
    mocker.patch.object(grim_audio, "shutdown_audio")
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


def test_replay_play_rejects_an_old_replay_before_opening_a_window(tmp_path, mocker) -> None:
    import grim.app as grim_app
    from crimson import runtime_boot

    # 0.10.0 recorded replay format v11, with the version inside a header map.
    old = {"header": {"replay_format_version": 11, "seed": 1}, "inputs": []}
    replay_path = write_payload_bytes(tmp_path, payload=msgspec.msgpack.encode(old), name="old.crd")
    boot = mocker.patch.object(runtime_boot, "boot_runtime")
    run_view = mocker.patch.object(grim_app, "run_view")

    result = CliRunner().invoke(app, ["replay", "play", str(replay_path), "--base-dir", str(tmp_path)])

    assert result.exit_code == 1
    assert "unsupported replay format version: 11" in result.output
    boot.assert_not_called()
    run_view.assert_not_called()
