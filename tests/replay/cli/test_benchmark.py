from __future__ import annotations

import json
from pathlib import Path

import msgspec
from typer.testing import CliRunner

from crimson.cli.app import app
from crimson.game_modes import GameMode
from tests.replay.cli._helpers import (
    build_replay as _build_replay,
)
from tests.replay.cli._helpers import (
    write_replay as _write_replay,
)


def test_replay_benchmark_human_success_outputs_throughput_stats(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "replay",
            "benchmark",
            str(replay_path),
            "--runs",
            "2",
            "--warmup-runs",
            "0",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "ok:" in result.output
    assert "wall_ms_p50=" in result.output
    assert "throughput_tps" in result.output
    assert "realtime_x" in result.output
    assert "json_report=" not in result.output


def test_replay_benchmark_json_output_payload_ok(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "replay",
            "benchmark",
            str(replay_path),
            "--runs",
            "2",
            "--warmup-runs",
            "0",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == 4
    assert payload["status"] == "ok"
    assert payload["replay"] == str(replay_path)
    assert payload["settings"]["runs"] == 2
    assert payload["settings"]["warmup_runs"] == 0
    assert payload["settings"]["mode"] == "headless"
    assert payload["benchmark"]["sample_count"] == 2
    assert len(payload["benchmark"]["samples"]) == 2
    assert payload["profile"] is None
    assert payload["render_telemetry"] is None
    assert payload["ticks"] == 2
    assert payload["run_result"] == json.loads(msgspec.json.encode(replay.result))


def test_replay_benchmark_headless_rejects_render_telemetry_flag(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "replay",
            "benchmark",
            str(replay_path),
            "--mode",
            "headless",
            "--render-telemetry",
        ],
    )

    assert result.exit_code == 1
    assert "--render-telemetry is supported only with --mode render" in result.output


def test_replay_benchmark_profile_outputs_hotspots_and_pstats(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()
    profile_out = tmp_path / "replay-benchmark.pstats"

    result = runner.invoke(
        app,
        [
            "replay",
            "benchmark",
            str(replay_path),
            "--runs",
            "1",
            "--warmup-runs",
            "0",
            "--format",
            "json",
            "--profile",
            "--top",
            "5",
            "--profile-out",
            str(profile_out),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    profile = payload["profile"]
    assert profile is not None
    assert profile["sort"] == "cumtime"
    assert profile["top"] == 5
    assert profile["source"] in ("project", "all")
    assert isinstance(profile["hotspots"], list)
    assert len(profile["hotspots"]) <= 5
    assert profile_out.is_file()

