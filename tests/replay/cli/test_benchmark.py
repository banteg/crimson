from __future__ import annotations

import json
from pathlib import Path

import msgspec
from typer.testing import CliRunner

from crimson.cli.app import app
from crimson.game_modes import GameMode
from crimson.replay.driver.replay_benchmark import run_replay_benchmark
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
    assert payload["ticks"] == 2
    assert payload["run_result"] == json.loads(msgspec.json.encode(replay.result))


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



def test_progress_keeps_benchmark_results_and_stdout_clean(capsys) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    quiet = run_replay_benchmark(replay, runs=1, warmup_runs=0, show_progress=False)
    shown = run_replay_benchmark(replay, runs=1, warmup_runs=1, show_progress=True)
    assert shown.run_result == quiet.run_result
    assert shown.ticks == quiet.ticks == 3
    assert capsys.readouterr().out == ""
