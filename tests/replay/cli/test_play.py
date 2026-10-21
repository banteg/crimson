from __future__ import annotations

import msgspec
import pytest
from typer.testing import CliRunner

from crimson.cli.app import app
from tests.replay.cli._helpers import write_payload_bytes


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


@pytest.mark.parametrize("fail", [False, True])
def test_replay_rtx_window_hooks_and_audio_cleanup(tmp_path, mocker, fail) -> None:
    from types import SimpleNamespace

    import grim.app as grim_app
    import grim.audio as grim_audio
    from crimson import runtime_boot
    from crimson.game_modes import GameMode
    from crimson.modes import replay_playback_mode
    from crimson.screens import replay_viewer
    from tests.replay.cli._helpers import build_replay, write_replay

    replay_path = write_replay(tmp_path, replay=build_replay(mode=GameMode.SURVIVAL, ticks=1), name="test.crd")
    mocker.patch.object(runtime_boot, "boot_runtime", return_value=SimpleNamespace(config=None, console=None, width=320, height=240))
    mocker.patch.object(replay_playback_mode, "open_replay_audio", return_value=None)
    shutdown = mocker.patch.object(grim_audio, "shutdown_audio")
    viewer = mocker.patch.object(replay_viewer, "ReplayViewer")
    mocker.patch.object(replay_viewer, "replay_card")
    states = []

    def run(*args, **kwargs):
        wants_edr = kwargs["hooks"].wants_edr
        states.append(wants_edr is not None and wants_edr())
        if fail:
            raise RuntimeError("window failed")

    mocker.patch.object(grim_app, "run_view", side_effect=run)
    for flags in (["--rtx"], [], ["--rtx-smoke"], ["--rtx", "--no-rtx-smoke"], ["--no-rtx-smoke"]):
        result = CliRunner().invoke(app, ["replay", "play", str(replay_path), "--base-dir", str(tmp_path), *flags])
        assert result.exit_code == (1 if fail else 0), result.exception
        assert viewer.call_args.kwargs["rtx"] == any(flag in flags for flag in ("--rtx", "--rtx-smoke"))
        assert viewer.call_args.kwargs["rtx_smoke"] == ("--no-rtx-smoke" not in flags)
    assert states == [True, False, True, True, False]
    assert shutdown.call_count == 5
