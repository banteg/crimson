from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import cast

from click import unstyle
from typer.testing import CliRunner

from crimson.cli import app
from crimson.game_modes import GameMode
from crimson.replay import Replay, ReplayHeader, ReplayRecorder, UnknownEvent, dump_replay
from crimson.replay.checkpoints import (
    FORMAT_VERSION,
    ReplayCheckpoints,
    default_checkpoints_path,
    dump_checkpoints_file,
    load_checkpoints_file,
)
from crimson.sim.driver.replay_benchmark import BenchmarkAggregate, BenchmarkSample, ReplayBenchmarkResult
from crimson.sim.driver.replay_render import ReplayRenderResult
from crimson.sim.driver.replay_runner import run_replay
from crimson.sim.driver.setup import RunResult
from crimson.sim.input import PlayerInput
from grim.geom import Vec2


def _build_replay(*, mode: GameMode, ticks: int, seed: int = 0xBEEF) -> Replay:
    header = ReplayHeader(
        game_mode_id=int(mode),
        seed=int(seed),
        tick_rate=60,
        player_count=1,
    )
    recorder = ReplayRecorder(header)
    for _ in range(int(ticks)):
        recorder.record_tick([PlayerInput(aim=Vec2(512.0, 512.0))])
    return recorder.finish()


def _write_replay(tmp_path: Path, *, replay: Replay, name: str) -> Path:
    replay_path = tmp_path / name
    replay_path.parent.mkdir(parents=True, exist_ok=True)
    replay_path.write_bytes(dump_replay(replay))
    return replay_path


def _write_checkpoint_sidecar(
    replay_path: Path,
    replay: Replay,
    *,
    mutate_command_hash: bool = False,
    mutate_replay_sha256: bool = False,
) -> Path:
    checkpoint_ticks = {0}
    checkpoints = []
    run_replay(replay, checkpoints_out=checkpoints, checkpoint_ticks=checkpoint_ticks)
    if mutate_command_hash:
        checkpoints[0] = replace(checkpoints[0], command_hash="deadbeef")
    replay_sha256 = hashlib.sha256(replay_path.read_bytes()).hexdigest()
    payload = ReplayCheckpoints(
        version=int(FORMAT_VERSION),
        replay_sha256=str(replay_sha256),
        sample_rate=1,
        checkpoints=list(checkpoints),
    )
    if mutate_replay_sha256:
        mismatch = "0" * 64
        if mismatch == str(replay_sha256):
            mismatch = "f" * 64
        payload = replace(payload, replay_sha256=mismatch)
    sidecar_path = default_checkpoints_path(replay_path)
    dump_checkpoints_file(sidecar_path, payload)
    return sidecar_path


def test_replay_list_shows_replays_under_base_dir(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=1)
    _write_replay(tmp_path / "replays", replay=replay, name="zeta.crd")
    _write_replay(tmp_path / "replays", replay=replay, name="alpha.crd")
    _write_replay(tmp_path / "replays" / "nested", replay=replay, name="nested.crd")
    (tmp_path / "replays" / "ignore.txt").write_text("x", encoding="utf-8")
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["replay", "list", "--base-dir", str(tmp_path)],
    )

    assert result.exit_code == 0, result.output
    lines = [line.strip() for line in result.output.splitlines() if line.strip()]
    assert lines == ["alpha.crd", "nested/nested.crd", "zeta.crd", "count=3"]


def test_replay_list_reports_when_no_replays_found(tmp_path: Path) -> None:
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["replay", "list", "--base-dir", str(tmp_path)],
    )

    assert result.exit_code == 0, result.output
    assert f"no replay files found under {tmp_path / 'replays'}" in result.output


def test_replay_verify_human_success_outputs_run_stats(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()

    result = runner.invoke(app, ["replay", "verify", str(replay_path)])

    assert result.exit_code == 0, result.output
    assert "ok:" in result.output
    assert "ticks=" in result.output
    assert "score_xp=" in result.output
    assert "kills=" in result.output


def test_replay_verify_json_output_payload_ok(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()

    result = runner.invoke(app, ["replay", "verify", str(replay_path), "--format", "json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == 1
    assert payload["status"] == "ok"
    assert payload["replay"] == str(replay_path)
    assert isinstance(payload["replay_sha256"], str)
    assert payload["score_claim"] is None
    assert payload["run_result"]["ticks"] == 2
    assert payload["run_result"]["score_xp"] == 0


def test_replay_verify_submitted_score_match_exit_zero(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "replay",
            "verify",
            str(replay_path),
            "--format",
            "json",
            "--submitted-score",
            "0",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "ok"
    assert payload["score_claim"]["metric"] == "score_xp"
    assert payload["score_claim"]["match"] is True


def test_replay_verify_submitted_score_mismatch_exit_three(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "replay",
            "verify",
            str(replay_path),
            "--format",
            "json",
            "--submitted-score",
            "1",
        ],
    )

    assert result.exit_code == 3, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "score_mismatch"
    assert payload["score_claim"]["metric"] == "score_xp"
    assert payload["score_claim"]["match"] is False


def test_replay_verify_is_strict_by_default(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay.events.append(UnknownEvent(tick_index=0, kind="unknown_event", payload=[]))
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()

    result = runner.invoke(app, ["replay", "verify", str(replay_path)])

    assert result.exit_code == 1
    assert "unsupported replay event kind" in result.output


def test_replay_verify_can_run_lenient_event_mode(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay.events.append(UnknownEvent(tick_index=0, kind="unknown_event", payload=[]))
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()

    result = runner.invoke(app, ["replay", "verify", str(replay_path), "--lenient-events"])

    assert result.exit_code == 0, result.output
    assert "ok:" in result.output


def test_replay_verify_auto_metric_uses_elapsed_ms_for_rush(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.RUSH, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="rush.crd")
    expected_elapsed_ms = run_replay(replay).elapsed_ms
    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "replay",
            "verify",
            str(replay_path),
            "--format",
            "json",
            "--submitted-score",
            str(expected_elapsed_ms),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["score_claim"]["metric"] == "elapsed_ms"
    assert payload["score_claim"]["simulated_value"] == int(expected_elapsed_ms)
    assert payload["score_claim"]["match"] is True


def test_replay_verify_json_out_works_for_human_and_json_output(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()
    human_out = tmp_path / "verify-human.json"
    json_out = tmp_path / "verify-json.json"

    human_result = runner.invoke(
        app,
        [
            "replay",
            "verify",
            str(replay_path),
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
            "verify",
            str(replay_path),
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
    assert payload["schema_version"] == 1
    assert payload["status"] == "ok"
    assert payload["replay"] == str(replay_path)
    assert isinstance(payload["replay_sha256"], str)
    assert payload["settings"]["runs"] == 2
    assert payload["settings"]["warmup_runs"] == 0
    assert payload["settings"]["mode"] == "headless"
    assert payload["benchmark"]["sample_count"] == 2
    assert len(payload["benchmark"]["samples"]) == 2
    assert payload["profile"] is None
    assert payload["run_result"]["ticks"] == 2


def test_replay_benchmark_render_mode_uses_render_runner(tmp_path: Path, monkeypatch) -> None:
    import crimson.sim.driver.replay_benchmark as replay_benchmark_mod

    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()
    calls: list[dict[str, object]] = []

    def fake_render_benchmark(_replay: Replay, **kwargs: object) -> ReplayBenchmarkResult:
        calls.append(dict(kwargs))
        run_result = RunResult(
            game_mode_id=int(GameMode.SURVIVAL),
            tick_rate=60,
            ticks=3,
            elapsed_ms=50,
            score_xp=42,
            creature_kill_count=1,
            most_used_weapon_id=1,
            shots_fired=2,
            shots_hit=1,
            rng_state=123,
        )
        sample = BenchmarkSample(wall_ms=1.5, ticks_per_second=2000.0, realtime_x=33.3)
        aggregate = BenchmarkAggregate(min=1.5, p50=1.5, mean=1.5, p95=1.5, max=1.5, stdev=0.0)
        return ReplayBenchmarkResult(
            run_result=run_result,
            samples=(sample,),
            wall_ms=aggregate,
            ticks_per_second=aggregate,
            realtime_x=aggregate,
            profile=None,
        )

    monkeypatch.setattr(replay_benchmark_mod, "run_replay_render_benchmark", fake_render_benchmark)

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
            "--lenient-events",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["settings"]["mode"] == "render"
    assert payload["run_result"]["score_xp"] == 42
    assert calls
    assert calls[0]["strict_events"] is False
    assert calls[0]["runs"] == 1
    assert calls[0]["warmup_runs"] == 0
    assert calls[0]["replay_path"] == replay_path
    assert calls[0]["base_dir"] == tmp_path


def test_replay_render_uses_render_video_runner(tmp_path: Path, monkeypatch) -> None:
    import crimson.sim.driver.replay_render as replay_render_mod

    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()
    calls: list[dict[str, object]] = []

    def fake_render(_replay: Replay, **kwargs: object) -> ReplayRenderResult:
        calls.append(dict(kwargs))
        run_result = RunResult(
            game_mode_id=int(GameMode.SURVIVAL),
            tick_rate=60,
            ticks=3,
            elapsed_ms=50,
            score_xp=42,
            creature_kill_count=1,
            most_used_weapon_id=1,
            shots_fired=2,
            shots_hit=1,
            rng_state=123,
        )
        return ReplayRenderResult(
            output_path=cast("Path", kwargs["output_path"]),
            frame_count=120,
            fps=60,
            width=1280,
            height=720,
            run_result=run_result,
        )

    monkeypatch.setattr(replay_render_mod, "run_replay_render_video", fake_render)

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
            "--lenient-events",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "ok: output=" in result.output
    assert "frames=120" in result.output
    assert calls
    assert calls[0]["strict_events"] is False
    assert calls[0]["fps"] == 60
    assert calls[0]["crf"] == 14
    assert calls[0]["preset"] == "slow"
    assert calls[0]["pixel_format"] == "yuv420p"
    assert calls[0]["overwrite"] is True
    assert calls[0]["mute_audio"] is False
    assert calls[0]["replay_path"] == replay_path
    assert calls[0]["base_dir"] == tmp_path
    assert calls[0]["output_path"] == replay_path.with_suffix(".render.mp4")


def test_replay_render_progress_callback_uses_separate_video_audio_bars(monkeypatch) -> None:
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

    monkeypatch.setattr(cli_mod, "tqdm", fake_tqdm)

    callback, close = cli_mod._replay_render_progress_callback(total_ticks=10, render_audio=True)
    assert callback is not None
    assert close is not None
    assert len(bars) == 1
    video_bar = bars[0]

    callback("video", 3, 5, 10)
    callback("audio", 0, 4, 10)
    callback("video", 4, 10, 10)
    callback("audio", 0, 10, 10)
    close()

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


def test_replay_render_uses_custom_output_and_ffmpeg_bin(tmp_path: Path, monkeypatch) -> None:
    import crimson.sim.driver.replay_render as replay_render_mod

    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    out_path = tmp_path / "exports" / "clip.mp4"
    ffmpeg_path = tmp_path / "bin" / "ffmpeg"
    runner = CliRunner()
    calls: list[dict[str, object]] = []

    def fake_render(_replay: Replay, **kwargs: object) -> ReplayRenderResult:
        calls.append(dict(kwargs))
        run_result = RunResult(
            game_mode_id=int(GameMode.SURVIVAL),
            tick_rate=60,
            ticks=2,
            elapsed_ms=33,
            score_xp=0,
            creature_kill_count=0,
            most_used_weapon_id=1,
            shots_fired=0,
            shots_hit=0,
            rng_state=123,
        )
        return ReplayRenderResult(
            output_path=cast("Path", kwargs["output_path"]),
            frame_count=2,
            fps=60,
            width=1024,
            height=768,
            run_result=run_result,
        )

    monkeypatch.setattr(replay_render_mod, "run_replay_render_video", fake_render)

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
    assert calls
    assert calls[0]["output_path"] == out_path
    assert calls[0]["ffmpeg_bin"] == ffmpeg_path
    assert calls[0]["mute_audio"] is False


def test_replay_render_supports_mute_audio_flag(tmp_path: Path, monkeypatch) -> None:
    import crimson.sim.driver.replay_render as replay_render_mod

    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=2)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    runner = CliRunner()
    calls: list[dict[str, object]] = []

    def fake_render(_replay: Replay, **kwargs: object) -> ReplayRenderResult:
        calls.append(dict(kwargs))
        run_result = RunResult(
            game_mode_id=int(GameMode.SURVIVAL),
            tick_rate=60,
            ticks=2,
            elapsed_ms=33,
            score_xp=0,
            creature_kill_count=0,
            most_used_weapon_id=1,
            shots_fired=0,
            shots_hit=0,
            rng_state=123,
        )
        return ReplayRenderResult(
            output_path=cast("Path", kwargs["output_path"]),
            frame_count=2,
            fps=60,
            width=1024,
            height=768,
            run_result=run_result,
        )

    monkeypatch.setattr(replay_render_mod, "run_replay_render_video", fake_render)

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
    assert calls
    assert calls[0]["mute_audio"] is True


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


def test_replay_benchmark_is_strict_by_default(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay.events.append(UnknownEvent(tick_index=0, kind="unknown_event", payload=[]))
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

    assert result.exit_code == 1
    assert "replay benchmark failed" in result.output
    assert "unsupported replay event kind" in result.output


def test_replay_benchmark_can_run_lenient_event_mode(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=1)
    replay.events.append(UnknownEvent(tick_index=0, kind="unknown_event", payload=[]))
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

    assert result.exit_code == 0, result.output
    assert "ok:" in result.output


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


def test_replay_verify_checkpoints_falls_back_to_legacy_sidecar_name(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    checkpoint_ticks = {0}
    checkpoints = []
    run_replay(replay, checkpoints_out=checkpoints, checkpoint_ticks=checkpoint_ticks)
    replay_sha256 = hashlib.sha256(replay_path.read_bytes()).hexdigest()
    dump_checkpoints_file(
        tmp_path / "survival.checkpoints.json.gz",
        ReplayCheckpoints(
            version=int(FORMAT_VERSION),
            replay_sha256=str(replay_sha256),
            sample_rate=1,
            checkpoints=list(checkpoints),
        ),
    )
    runner = CliRunner()

    result = runner.invoke(app, ["replay", "verify-checkpoints", str(replay_path)])

    assert result.exit_code == 0, result.output
    assert "checkpoints match" in result.output


def test_replay_verify_checkpoints_reports_mismatch(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    _write_checkpoint_sidecar(replay_path, replay, mutate_command_hash=True)
    runner = CliRunner()

    result = runner.invoke(app, ["replay", "verify-checkpoints", str(replay_path)])

    assert result.exit_code == 1
    assert "checkpoint command mismatch at tick=0" in result.output


def test_replay_verify_checkpoints_fails_on_sha_mismatch_by_default(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    _write_checkpoint_sidecar(replay_path, replay, mutate_replay_sha256=True)
    runner = CliRunner()

    result = runner.invoke(app, ["replay", "verify-checkpoints", str(replay_path)])

    assert result.exit_code == 1
    assert "replay_sha256 mismatch" in result.output


def test_replay_verify_checkpoints_can_run_lenient_integrity(tmp_path: Path) -> None:
    replay = _build_replay(mode=GameMode.SURVIVAL, ticks=3)
    replay_path = _write_replay(tmp_path, replay=replay, name="survival.crd")
    sidecar = _write_checkpoint_sidecar(replay_path, replay, mutate_replay_sha256=True)
    runner = CliRunner()

    result = runner.invoke(app, ["replay", "verify-checkpoints", str(replay_path), "--lenient-integrity"])

    assert result.exit_code == 0, result.output
    assert "warning: checkpoints replay_sha256 mismatch" in result.output
    loaded = load_checkpoints_file(sidecar)
    assert loaded.replay_sha256 != hashlib.sha256(replay_path.read_bytes()).hexdigest()


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
