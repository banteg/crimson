from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from click import unstyle
from typer.testing import CliRunner

from crimson.cli import app
from crimson.game_modes import GameMode
from crimson.replay.checkpoints import FORMAT_VERSION, ReplayCheckpoints, dump_checkpoints_file
from crimson.replay.driver.replay_benchmark import (
    BenchmarkAggregate,
    BenchmarkSample,
    ReplayBenchmarkResult,
    ReplayRenderTelemetryArtifacts,
    ReplayRenderTelemetryFrame,
    ReplayRenderTelemetryResult,
    ReplayRenderTelemetrySummary,
    ReplayRenderTelemetryTopTick,
)
from crimson.replay.driver.replay_render import ReplayRenderResult
from crimson.replay.driver.setup import RunResult
from crimson.sim.input_providers import PerkPickCommand
from crimson.weapons import WeaponId
from tests.replay.cli._helpers import (
    build_replay as _build_replay,
)
from tests.replay.cli._helpers import (
    inject_tick_commands as _inject_tick_commands,
)
from tests.replay.cli._helpers import (
    write_checkpoint_sidecar as _write_checkpoint_sidecar,
)
from tests.replay.cli._helpers import (
    write_replay as _write_replay,
)
from tests.support.replay_runner_helpers import _run_verify_playback


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
    assert payload["schema_version"] == 3
    assert payload["status"] == "ok"
    assert payload["replay"] == str(replay_path)
    assert payload["settings"]["runs"] == 2
    assert payload["settings"]["warmup_runs"] == 0
    assert payload["settings"]["mode"] == "headless"
    assert payload["benchmark"]["sample_count"] == 2
    assert len(payload["benchmark"]["samples"]) == 2
    assert payload["profile"] is None
    assert payload["render_telemetry"] is None
    assert payload["run_result"]["ticks"] == 2


def test_replay_benchmark_render_mode_uses_render_runner(tmp_path: Path, mocker) -> None:
    import crimson.replay.driver.replay_benchmark as replay_benchmark_mod

    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()
    run_result = RunResult(
        game_mode_id=GameMode.SURVIVAL,
        tick_rate=60,
        ticks=3,
        elapsed_ms=50,
        score_xp=42,
        creature_kill_count=1,
        most_used_weapon_id=WeaponId.PISTOL,
        shots_fired=2,
        shots_hit=1,
        rng_state=123,
    )
    sample = BenchmarkSample(wall_ms=1.5, ticks_per_second=2000.0, realtime_x=33.3)
    aggregate = BenchmarkAggregate(min=1.5, p50=1.5, mean=1.5, p95=1.5, max=1.5, stdev=0.0)
    run_replay_render_benchmark = mocker.patch.object(
        replay_benchmark_mod,
        "run_replay_render_benchmark",
        return_value=ReplayBenchmarkResult(
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
    assert payload["run_result"]["score_xp"] == 42
    run_replay_render_benchmark.assert_called_once()
    kwargs = run_replay_render_benchmark.call_args.kwargs
    assert kwargs["runs"] == 1
    assert kwargs["warmup_runs"] == 0
    assert kwargs["rtx"] is False
    assert kwargs["show_progress"] is False
    assert kwargs["replay_path"] == replay_path
    assert kwargs["base_dir"] == tmp_path


def test_replay_benchmark_render_mode_defaults_to_single_run_no_warmup(tmp_path: Path, mocker) -> None:
    import crimson.replay.driver.replay_benchmark as replay_benchmark_mod

    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()
    run_result = RunResult(
        game_mode_id=GameMode.SURVIVAL,
        tick_rate=60,
        ticks=3,
        elapsed_ms=50,
        score_xp=42,
        creature_kill_count=1,
        most_used_weapon_id=WeaponId.PISTOL,
        shots_fired=2,
        shots_hit=1,
        rng_state=123,
    )
    sample = BenchmarkSample(wall_ms=1.5, ticks_per_second=2000.0, realtime_x=33.3)
    aggregate = BenchmarkAggregate(min=1.5, p50=1.5, mean=1.5, p95=1.5, max=1.5, stdev=0.0)
    run_replay_render_benchmark = mocker.patch.object(
        replay_benchmark_mod,
        "run_replay_render_benchmark",
        return_value=ReplayBenchmarkResult(
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
        ],
    )

    assert result.exit_code == 0, result.output
    run_replay_render_benchmark.assert_called_once()
    kwargs = run_replay_render_benchmark.call_args.kwargs
    assert kwargs["runs"] == 1
    assert kwargs["warmup_runs"] == 0
    assert kwargs["rtx"] is False
    assert kwargs["show_progress"] is True


def test_replay_benchmark_render_mode_passes_rtx_flag(tmp_path: Path, mocker) -> None:
    import crimson.replay.driver.replay_benchmark as replay_benchmark_mod

    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()
    run_result = RunResult(
        game_mode_id=GameMode.SURVIVAL,
        tick_rate=60,
        ticks=3,
        elapsed_ms=50,
        score_xp=42,
        creature_kill_count=1,
        most_used_weapon_id=WeaponId.PISTOL,
        shots_fired=2,
        shots_hit=1,
        rng_state=123,
    )
    sample = BenchmarkSample(wall_ms=1.5, ticks_per_second=2000.0, realtime_x=33.3)
    aggregate = BenchmarkAggregate(min=1.5, p50=1.5, mean=1.5, p95=1.5, max=1.5, stdev=0.0)
    run_replay_render_benchmark = mocker.patch.object(
        replay_benchmark_mod,
        "run_replay_render_benchmark",
        return_value=ReplayBenchmarkResult(
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
            "--rtx",
            "--base-dir",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 0, result.output
    run_replay_render_benchmark.assert_called_once()
    kwargs = run_replay_render_benchmark.call_args.kwargs
    assert kwargs["rtx"] is True


def test_replay_benchmark_headless_defaults_remain_five_and_one(tmp_path: Path, mocker) -> None:
    import crimson.replay.driver.replay_benchmark as replay_benchmark_mod

    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()
    run_result = RunResult(
        game_mode_id=GameMode.SURVIVAL,
        tick_rate=60,
        ticks=3,
        elapsed_ms=50,
        score_xp=42,
        creature_kill_count=1,
        most_used_weapon_id=WeaponId.PISTOL,
        shots_fired=2,
        shots_hit=1,
        rng_state=123,
    )
    sample = BenchmarkSample(wall_ms=1.5, ticks_per_second=2000.0, realtime_x=33.3)
    aggregate = BenchmarkAggregate(min=1.5, p50=1.5, mean=1.5, p95=1.5, max=1.5, stdev=0.0)
    run_replay_benchmark = mocker.patch.object(
        replay_benchmark_mod,
        "run_replay_benchmark",
        return_value=ReplayBenchmarkResult(
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
            "headless",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    run_replay_benchmark.assert_called_once()
    kwargs = run_replay_benchmark.call_args.kwargs
    assert kwargs["runs"] == 5
    assert kwargs["warmup_runs"] == 1
    assert kwargs["show_progress"] is False


def test_replay_benchmark_headless_human_format_enables_progress(tmp_path: Path, mocker) -> None:
    import crimson.replay.driver.replay_benchmark as replay_benchmark_mod

    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()
    run_result = RunResult(
        game_mode_id=GameMode.SURVIVAL,
        tick_rate=60,
        ticks=3,
        elapsed_ms=50,
        score_xp=42,
        creature_kill_count=1,
        most_used_weapon_id=WeaponId.PISTOL,
        shots_fired=2,
        shots_hit=1,
        rng_state=123,
    )
    sample = BenchmarkSample(wall_ms=1.5, ticks_per_second=2000.0, realtime_x=33.3)
    aggregate = BenchmarkAggregate(min=1.5, p50=1.5, mean=1.5, p95=1.5, max=1.5, stdev=0.0)
    run_replay_benchmark = mocker.patch.object(
        replay_benchmark_mod,
        "run_replay_benchmark",
        return_value=ReplayBenchmarkResult(
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
            "headless",
        ],
    )

    assert result.exit_code == 0, result.output
    run_replay_benchmark.assert_called_once()
    kwargs = run_replay_benchmark.call_args.kwargs
    assert kwargs["show_progress"] is True


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


def test_replay_benchmark_headless_rejects_rtx_flag(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
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
            "--rtx",
            "--base-dir",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 1
    assert "--rtx is supported only with --mode render" in result.output


def test_replay_benchmark_render_mode_passes_extended_profiling_kwargs(tmp_path: Path, mocker) -> None:
    import crimson.replay.driver.replay_benchmark as replay_benchmark_mod

    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()
    run_result = RunResult(
        game_mode_id=GameMode.SURVIVAL,
        tick_rate=60,
        ticks=3,
        elapsed_ms=50,
        score_xp=42,
        creature_kill_count=1,
        most_used_weapon_id=WeaponId.PISTOL,
        shots_fired=2,
        shots_hit=1,
        rng_state=123,
    )
    sample = BenchmarkSample(wall_ms=1.5, ticks_per_second=2000.0, realtime_x=33.3)
    aggregate = BenchmarkAggregate(min=1.5, p50=1.5, mean=1.5, p95=1.5, max=1.5, stdev=0.0)
    telemetry_frame = ReplayRenderTelemetryFrame(
        frame_index=0,
        tick_index_before_update=0,
        tick_index_after_update=1,
        update_ms=0.2,
        draw_ms=0.6,
        frame_ms=0.8,
        draw_calls_total=12,
        draw_calls_by_api={"draw_texture_pro": 8},
        draw_calls_by_pass={"projectiles_effects": 8},
        pass_ms={"projectiles_effects": 0.6},
    )
    telemetry_summary = ReplayRenderTelemetrySummary(
        frame_ms=aggregate,
        update_ms=aggregate,
        draw_ms=aggregate,
        draw_calls_total=aggregate,
        top_draw_ms_ticks=(ReplayRenderTelemetryTopTick(tick_index=1, frame_index=0, value=0.6),),
        top_frame_ms_ticks=(ReplayRenderTelemetryTopTick(tick_index=1, frame_index=0, value=0.8),),
        top_draw_calls_ticks=(ReplayRenderTelemetryTopTick(tick_index=1, frame_index=0, value=12.0),),
    )
    telemetry_artifacts = ReplayRenderTelemetryArtifacts(
        telemetry_json_path=tmp_path / "telemetry.json",
        charts_dir=tmp_path / "charts",
        frame_timing_svg=tmp_path / "charts" / "frame_timing.svg",
        draw_calls_svg=tmp_path / "charts" / "draw_calls.svg",
        pass_timing_stacked_svg=tmp_path / "charts" / "pass_timing_stacked.svg",
        report_md=tmp_path / "charts" / "report.md",
    )
    run_replay_render_benchmark = mocker.patch.object(
        replay_benchmark_mod,
        "run_replay_render_benchmark",
        return_value=ReplayBenchmarkResult(
            run_result=run_result,
            samples=(sample,),
            wall_ms=aggregate,
            ticks_per_second=aggregate,
            realtime_x=aggregate,
            profile=None,
            render_telemetry=ReplayRenderTelemetryResult(
                frames=(telemetry_frame,),
                summary=telemetry_summary,
                artifacts=telemetry_artifacts,
                preview=(telemetry_frame,),
            ),
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
            "--render-telemetry",
            "--render-telemetry-out",
            str(tmp_path / "telemetry.json"),
            "--render-charts-out-dir",
            str(tmp_path / "charts"),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == 3
    assert payload["render_telemetry"] is not None
    assert payload["render_telemetry"]["summary"]["top_draw_ms_ticks"][0]["tick_index"] == 1

    run_replay_render_benchmark.assert_called_once()
    kwargs = run_replay_render_benchmark.call_args.kwargs
    assert kwargs["render_telemetry"] is True
    assert kwargs["render_telemetry_out"] == (tmp_path / "telemetry.json")
    assert kwargs["render_charts_out_dir"] == (tmp_path / "charts")


def test_replay_render_uses_render_video_runner(tmp_path: Path, mocker) -> None:
    import crimson.replay.driver.replay_render as replay_render_mod

    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()
    run_result = RunResult(
        game_mode_id=GameMode.SURVIVAL,
        tick_rate=60,
        ticks=3,
        elapsed_ms=50,
        score_xp=42,
        creature_kill_count=1,
        most_used_weapon_id=WeaponId.PISTOL,
        shots_fired=2,
        shots_hit=1,
        rng_state=123,
    )
    run_replay_render_video = mocker.patch.object(
        replay_render_mod,
        "run_replay_render_video",
        side_effect=lambda _replay, **kwargs: ReplayRenderResult(
            output_path=cast("Path", kwargs["output_path"]),
            frame_count=120,
            fps=60,
            width=1280,
            height=720,
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


def test_replay_render_progress_runtime_uses_separate_video_audio_bars(mocker) -> None:
    import crimson.cli as cli_mod

    class _FakeBar:
        def __init__(self, *, total: int, desc: str) -> None:
            self.total = int(total)
            self.desc = str(desc)
            self.updates: list[int] = []
            self.postfixes: list[dict[str, int]] = []
            self.closed = False

        def update(self, value: int) -> None:
            self.updates.append(int(value))

        def set_postfix(self, **kwargs: int) -> None:
            self.postfixes.append(dict(kwargs))

        def close(self) -> None:
            self.closed = True

    bars: list[_FakeBar] = []

    def fake_tqdm(*, total: int, unit: str, desc: str, leave: bool):
        assert unit == "tick"
        assert leave is True
        bar = _FakeBar(total=int(total), desc=str(desc))
        bars.append(bar)
        return bar

    mocker.patch.object(cli_mod, "tqdm", side_effect=fake_tqdm)

    progress = cli_mod._replay_render_progress_runtime(total_ticks=10, render_audio=True)
    assert progress is not None
    assert len(bars) == 1
    video_bar = bars[0]

    progress.update(phase="video", frame_count=3, tick_index=5, total_ticks=10)
    progress.update(phase="audio", frame_count=0, tick_index=4, total_ticks=10)
    progress.update(phase="video", frame_count=4, tick_index=10, total_ticks=10)
    progress.update(phase="audio", frame_count=0, tick_index=10, total_ticks=10)
    progress.close()

    assert len(bars) == 2
    audio_bar = bars[1]

    assert video_bar.desc == "replay video"
    assert video_bar.total == 10
    assert video_bar.updates == [5, 5]
    assert video_bar.postfixes[-1]["frames"] == 4
    assert video_bar.closed is True

    assert audio_bar.desc == "replay audio"
    assert audio_bar.total == 10
    assert audio_bar.updates == [4, 6]
    assert audio_bar.postfixes == []
    assert audio_bar.closed is True


def test_replay_render_uses_custom_output_and_ffmpeg_bin(tmp_path: Path, mocker) -> None:
    import crimson.replay.driver.replay_render as replay_render_mod

    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    out_path = tmp_path / "exports" / "clip.mp4"
    ffmpeg_path = tmp_path / "bin" / "ffmpeg"
    runner = CliRunner()
    run_result = RunResult(
        game_mode_id=GameMode.SURVIVAL,
        tick_rate=60,
        ticks=2,
        elapsed_ms=33,
        score_xp=0,
        creature_kill_count=0,
        most_used_weapon_id=WeaponId.PISTOL,
        shots_fired=0,
        shots_hit=0,
        rng_state=123,
    )
    run_replay_render_video = mocker.patch.object(
        replay_render_mod,
        "run_replay_render_video",
        side_effect=lambda _replay, **kwargs: ReplayRenderResult(
            output_path=cast("Path", kwargs["output_path"]),
            frame_count=2,
            fps=60,
            width=1024,
            height=768,
            run_result=run_result,
        ),
    )

    result = runner.invoke(
        app,
        [
            "replay",
            "render",
            str(replay_path),
            "--out",
            str(out_path),
            "--ffmpeg-bin",
            str(ffmpeg_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "output=" in result.output
    run_replay_render_video.assert_called_once()
    kwargs = run_replay_render_video.call_args.kwargs
    assert kwargs["output_path"] == out_path
    assert kwargs["ffmpeg_bin"] == ffmpeg_path
    assert kwargs["mute_audio"] is False


def test_replay_render_supports_mute_audio_flag(tmp_path: Path, mocker) -> None:
    import crimson.replay.driver.replay_render as replay_render_mod

    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()
    run_result = RunResult(
        game_mode_id=GameMode.SURVIVAL,
        tick_rate=60,
        ticks=2,
        elapsed_ms=33,
        score_xp=0,
        creature_kill_count=0,
        most_used_weapon_id=WeaponId.PISTOL,
        shots_fired=0,
        shots_hit=0,
        rng_state=123,
    )
    run_replay_render_video = mocker.patch.object(
        replay_render_mod,
        "run_replay_render_video",
        side_effect=lambda _replay, **kwargs: ReplayRenderResult(
            output_path=cast("Path", kwargs["output_path"]),
            frame_count=2,
            fps=60,
            width=1024,
            height=768,
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
            "--mute-audio",
        ],
    )

    assert result.exit_code == 0, result.output
    run_replay_render_video.assert_called_once()
    assert run_replay_render_video.call_args.kwargs["mute_audio"] is True


def test_replay_benchmark_json_out_works_for_human_and_json_output(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()
    human_out = tmp_path / "benchmark-human.json"
    json_out = tmp_path / "benchmark-json.json"

    human_result = runner.invoke(
        app,
        [
            "replay",
            "benchmark",
            str(replay_path),
            "--runs",
            "2",
            "--warmup-runs",
            "0",
            "--json-out",
            str(human_out),
        ],
    )
    assert human_result.exit_code == 0, human_result.output
    assert "json_report=" in human_result.output
    assert json.loads(human_out.read_text(encoding="utf-8"))["status"] == "ok"

    json_result = runner.invoke(
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
            "--json-out",
            str(json_out),
        ],
    )
    assert json_result.exit_code == 0, json_result.output
    stdout_payload = json.loads(json_result.output)
    file_payload = json.loads(json_out.read_text(encoding="utf-8"))
    assert stdout_payload["status"] == "ok"
    assert file_payload == stdout_payload


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


def test_replay_benchmark_stale_perk_pick_is_noop(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=1)
    _inject_tick_commands(replay, 0, [PerkPickCommand(player_index=0, choice_index=0)])
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()

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
        ],
    )

    assert result.exit_code == 0


def test_replay_benchmark_rejects_removed_lenient_events_option(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()

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
            "--lenient-events",
        ],
    )

    assert result.exit_code == 2
    output = unstyle(result.output)
    assert "No such option" in output
    assert "--lenient-events" in output


def test_replay_verify_rejects_checkpoints_option(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "replay",
            "verify",
            str(replay_path),
            "--checkpoints",
            str(tmp_path / "expected.crd.chk"),
        ],
    )

    assert result.exit_code == 2
    assert "No such option: --checkpoints" in unstyle(result.output)


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


def test_replay_verify_checkpoints_does_not_fall_back_to_legacy_sidecar_name(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    checkpoint_ticks = {0}
    checkpoints = []
    _run_verify_playback(replay, checkpoints_out=checkpoints, checkpoint_ticks=checkpoint_ticks)
    dump_checkpoints_file(
        tmp_path / "survival.checkpoints.json.gz",
        ReplayCheckpoints(
            version=int(FORMAT_VERSION),
            sample_rate=1,
            checkpoints=list(checkpoints),
        ),
    )
    runner = CliRunner()

    result = runner.invoke(app, ["replay", "verify-checkpoints", str(replay_path)])

    assert result.exit_code == 1
    assert "checkpoints file not found" in result.output


def test_replay_verify_checkpoints_reports_mismatch(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    _write_checkpoint_sidecar(replay_path, replay, mutate_checkpoint=True)
    runner = CliRunner()

    result = runner.invoke(app, ["replay", "verify-checkpoints", str(replay_path)])

    assert result.exit_code == 1


def test_replay_verify_checkpoints_rejects_removed_lenient_integrity_flag(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    _write_checkpoint_sidecar(replay_path, replay)
    runner = CliRunner()

    result = runner.invoke(app, ["replay", "verify-checkpoints", str(replay_path), "--lenient-integrity"])

    assert result.exit_code == 2
    assert "No such option" in unstyle(result.output)


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
