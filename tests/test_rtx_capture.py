from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

import pytest
from PIL import Image

from tools.rtx.capture import capture_replay, parse_ticks


def test_tick_list_ranges_sort_and_deduplicate():
    assert parse_ticks("500,490:496:2,494") == [490, 492, 494, 496, 500]


@pytest.mark.parametrize("text", ["", "1", "3,", "4:2", "2:5:0", "2:5:-1", "2:5:1:1", "2:100000", "x"])
def test_bad_tick_specifications_fail(text):
    with pytest.raises(argparse.ArgumentTypeError):
        parse_ticks(text)


def test_many_ticks_launch_one_client_and_publish_manifest(tmp_path, monkeypatch):
    replay = tmp_path / "run.crd"
    replay.write_bytes(b"test replay")
    out = tmp_path / "out"
    calls = []
    monkeypatch.setenv("CRIMSON_CAPTURE_TICK", "999")
    monkeypatch.setenv("CRIMSON_WATCH_MOMENTS", "1000")

    def run(command, *, env, **kwargs):
        calls.append((command, env))
        assert "CRIMSON_CAPTURE_TICK" not in env and "CRIMSON_WATCH_MOMENTS" not in env
        for tick in map(int, env["CRIMSON_CAPTURE_TICKS"].split(",")):
            Image.new("RGB", (2, 2), (tick, 0, 0)).save(Path(env["CRIMSON_CAPTURE"]) / f"tick_{tick}.ppm")

    monkeypatch.setattr("tools.rtx.capture.subprocess.run", run)
    result = capture_replay(game=tmp_path, replay=replay, ticks=[2, 5, 9], client=tmp_path / "client",
                            mode="rtx", out=out)
    assert len(calls) == 1
    assert result["ticks"] == [2, 5, 9] and result["continuous"]
    assert json.loads((out / "manifest.json").read_text())["ticks"] == [2, 5, 9]
    for tick in (2, 5, 9):
        with Image.open(out / f"tick_{tick}.png") as image:
            assert image.getpixel((0, 0)) == (tick, 0, 0)


def test_stale_outputs_cannot_hide_a_missing_frame(tmp_path, monkeypatch):
    replay = tmp_path / "run.crd"
    replay.write_bytes(b"test replay")
    out = tmp_path / "out"
    out.mkdir()
    Image.new("RGB", (2, 2)).save(out / "tick_5.ppm")
    (out / "manifest.json").write_text("stale")
    monkeypatch.setattr("tools.rtx.capture.subprocess.run", lambda *a, **kw: None)
    with pytest.raises(FileNotFoundError):
        capture_replay(game=tmp_path, replay=replay, ticks=[5], client=tmp_path / "client", mode="rtx", out=out)
    assert not (out / "manifest.json").exists()


@pytest.mark.parametrize("error", [subprocess.CalledProcessError(1, "client"), subprocess.TimeoutExpired("client", 1)])
def test_client_failure_points_to_log_and_does_not_publish_manifest(tmp_path, monkeypatch, error):
    replay = tmp_path / "run.crd"
    replay.write_bytes(b"test replay")
    out = tmp_path / "out"

    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr("tools.rtx.capture.subprocess.run", fail)
    with pytest.raises(RuntimeError, match="client.log"):
        capture_replay(game=tmp_path, replay=replay, ticks=[5], client=tmp_path / "client", mode="rtx", out=out)
    assert not (out / "manifest.json").exists()
