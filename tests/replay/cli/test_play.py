from __future__ import annotations

import msgspec
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
