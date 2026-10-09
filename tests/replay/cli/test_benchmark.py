from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import msgspec
from typer.testing import CliRunner

from crimson.cli.app import app
from crimson.game_modes import GameMode
from crimson.replay.driver.replay_benchmark import (
    BenchmarkAggregate,
    BenchmarkSample,
    ReplayBenchmarkResult,
)
from crimson.replay.driver.replay_render import ReplayRenderResult
from crimson.sim.run_result import PlayerRunResult, RunOutcome, RunResult
from crimson.weapons import WeaponId
from tests.replay.cli._helpers import (
    build_replay as _build_replay,
)
from tests.replay.cli._helpers import (
    write_checkpoint_sidecar as _write_checkpoint_sidecar,
)
from tests.replay.cli._helpers import (
    write_replay as _write_replay,
)


def _run_result(*, elapsed_ms: int, score_xp: int, kills: int, shots_fired: int, shots_hit: int) -> RunResult:
    return RunResult(
        outcome=RunOutcome.INCOMPLETE,
        elapsed_ms=elapsed_ms,
        kills=kills,
        shots_fired=shots_fired,
        shots_hit=shots_hit,
        rng_state=123,
        pending_perks=0,
        quest_final_ms=None,
        players=(
            PlayerRunResult(
                experience=score_xp,
                health=100.0,
                most_used_weapon_id=WeaponId.PISTOL,
            ),
        ),
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


def test_replay_benchmark_render_mode_uses_render_runner(tmp_path: Path, mocker) -> None:
    import crimson.replay.driver.replay_benchmark as replay_benchmark_mod

    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()
    run_result = _run_result(elapsed_ms=50, score_xp=42, kills=1, shots_fired=2, shots_hit=1)
    sample = BenchmarkSample(wall_ms=1.5, ticks_per_second=2000.0, realtime_x=33.3)
    aggregate = BenchmarkAggregate(min=1.5, p50=1.5, mean=1.5, p95=1.5, max=1.5, stdev=0.0)
    run_replay_render_benchmark = mocker.patch.object(
        replay_benchmark_mod,
        "run_replay_render_benchmark",
        return_value=ReplayBenchmarkResult(
            ticks=3,
            run_result=run_result,
            samples=(sample,),
            wall_ms=aggregate,
            ticks_per_second=aggregate,
            realtime_x=aggregate,
            profile=None,
        ),
    )

    result = runner.invoke(
        app,
        [
            "replay",
            "benchmark",
            str(replay_path),
            "--mode",
            "render",
            "--base-dir",
            str(tmp_path),
            "--runs",
            "1",
            "--warmup-runs",
            "0",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["settings"]["mode"] == "render"
    assert payload["run_result"]["players"][0]["experience"] == 42
    run_replay_render_benchmark.assert_called_once()
    kwargs = run_replay_render_benchmark.call_args.kwargs
    assert kwargs["runs"] == 1
    assert kwargs["warmup_runs"] == 0
    assert kwargs["rtx"] is False
    assert kwargs["show_progress"] is False
    assert kwargs["replay_path"] == replay_path
    assert kwargs["base_dir"] == tmp_path


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


def test_replay_render_uses_render_video_runner(tmp_path: Path, mocker) -> None:
    import crimson.replay.driver.replay_render as replay_render_mod

    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()
    run_result = _run_result(elapsed_ms=50, score_xp=42, kills=1, shots_fired=2, shots_hit=1)
    run_replay_render_video = mocker.patch.object(
        replay_render_mod,
        "run_replay_render_video",
        side_effect=lambda _replay, **kwargs: ReplayRenderResult(
            output_path=cast("Path", kwargs["output_path"]),
            frame_count=120,
            fps=60,
            width=1280,
            height=720,
            ticks=3,
            run_result=run_result,
        ),
    )

    result = runner.invoke(
        app,
        [
            "replay",
            "render",
            str(replay_path),
            "--base-dir",
            str(tmp_path),
            "--fps",
            "60",
            "--crf",
            "14",
            "--preset",
            "slow",
            "--pixel-format",
            "yuv420p",
            "--overwrite",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "ok: output=" in result.output
    assert "frames=120" in result.output
    run_replay_render_video.assert_called_once()
    kwargs = run_replay_render_video.call_args.kwargs
    assert kwargs["fps"] == 60
    assert kwargs["crf"] == 14
    assert kwargs["preset"] == "slow"
    assert kwargs["pixel_format"] == "yuv420p"
    assert kwargs["overwrite"] is True
    assert kwargs["mute_audio"] is False
    assert kwargs["replay_path"] == replay_path
    assert kwargs["base_dir"] == tmp_path
    assert kwargs["output_path"] == replay_path.with_suffix(".render.mp4")


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


def test_replay_verify_checkpoints_preserves_success_behavior(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    _write_checkpoint_sidecar(replay_path, replay)
    runner = CliRunner()

    result = runner.invoke(app, ["replay", "verify-checkpoints", str(replay_path)])

    assert result.exit_code == 0, result.output
    assert "checkpoints match" in result.output
    assert "score_xp=" in result.output
    assert "kills=" in result.output


def test_replay_verify_checkpoints_reports_mismatch(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    _write_checkpoint_sidecar(replay_path, replay, mutate_checkpoint=True)
    runner = CliRunner()

    result = runner.invoke(app, ["replay", "verify-checkpoints", str(replay_path)])

    assert result.exit_code == 1
    assert "checkpoint mismatch at tick=0" in result.output
    assert "first state diff: score_xp expected=999999 actual=0" in result.output


def test_replay_diff_checkpoints_still_reports_success(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    sidecar_a = _write_checkpoint_sidecar(replay_path, replay)
    sidecar_b = tmp_path / "actual.crd.chk"
    sidecar_b.write_bytes(sidecar_a.read_bytes())
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["replay", "diff-checkpoints", str(sidecar_a), str(sidecar_b)],
    )

    assert result.exit_code == 0, result.output
    assert "checkpoints match" in result.output
