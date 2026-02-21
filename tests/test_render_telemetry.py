from __future__ import annotations

import os
from pathlib import Path
from typing import Any, cast

import pytest

from crimson.render.world.profile_hooks import profile_pass
from crimson.sim.driver.render_telemetry import RenderTelemetrySession
from crimson.sim.driver.replay_benchmark import (
    BenchmarkAggregate,
    ReplayBenchmarkError,
    ReplayRenderTelemetryFrame,
    _RenderOnceResult,
    _run_with_pyspy,
    _summarize_render_telemetry,
)
from crimson.sim.driver.setup import RunResult


def _dummy_run_result() -> RunResult:
    return RunResult(
        game_mode_id=9,
        tick_rate=60,
        ticks=1,
        elapsed_ms=16,
        score_xp=0,
        creature_kill_count=0,
        most_used_weapon_id=1,
        shots_fired=0,
        shots_hit=0,
        rng_state=1,
    )


def test_render_telemetry_session_counts_calls_and_restores(monkeypatch) -> None:
    from grim.raylib_api import rl

    calls: list[str] = []

    def _draw_circle(*_args, **_kwargs) -> None:
        calls.append("draw_circle")

    def _draw_texture(*_args, **_kwargs) -> None:
        calls.append("draw_texture_pro")

    monkeypatch.setattr(rl, "draw_circle", _draw_circle, raising=False)
    monkeypatch.setattr(rl, "draw_texture_pro", _draw_texture, raising=False)

    original_circle = rl.draw_circle

    session = RenderTelemetrySession()
    with session:
        session.begin_frame(frame_index=0, tick_index_before_update=0)
        draw_circle = cast(Any, rl.draw_circle)
        draw_texture_pro = cast(Any, rl.draw_texture_pro)
        draw_circle(0, 0, 1.0, None)
        with profile_pass("projectiles_effects"):
            draw_texture_pro(None, None, None, None, 0.0, None)
        session.end_frame(
            tick_index_after_update=1,
            update_ms=0.2,
            draw_ms=0.6,
            frame_ms=0.8,
        )

    assert calls == ["draw_circle", "draw_texture_pro"]
    frames = session.frames
    assert len(frames) == 1
    frame = frames[0]
    assert frame.draw_calls_total == 2
    assert frame.draw_calls_by_api["draw_circle"] == 1
    assert frame.draw_calls_by_api["draw_texture_pro"] == 1
    assert frame.draw_calls_by_pass["_unscoped"] == 1
    assert frame.draw_calls_by_pass["projectiles_effects"] == 1
    assert frame.pass_ms["projectiles_effects"] >= 0.0
    assert rl.draw_circle is original_circle


def test_render_telemetry_summary_orders_top_ticks() -> None:
    frame_1 = ReplayRenderTelemetryFrame(
        frame_index=0,
        tick_index_before_update=0,
        tick_index_after_update=1,
        update_ms=0.1,
        draw_ms=0.4,
        frame_ms=0.5,
        draw_calls_total=10,
        draw_calls_by_api={},
        draw_calls_by_pass={},
        pass_ms={},
    )
    frame_2 = ReplayRenderTelemetryFrame(
        frame_index=1,
        tick_index_before_update=1,
        tick_index_after_update=2,
        update_ms=0.1,
        draw_ms=0.8,
        frame_ms=0.9,
        draw_calls_total=40,
        draw_calls_by_api={},
        draw_calls_by_pass={},
        pass_ms={},
    )

    summary = _summarize_render_telemetry(frames=(frame_1, frame_2))

    assert isinstance(summary.frame_ms, BenchmarkAggregate)
    assert summary.top_draw_ms_ticks[0].tick_index == 2
    assert summary.top_frame_ms_ticks[0].tick_index == 2
    assert summary.top_draw_calls_ticks[0].tick_index == 2


def test_run_with_pyspy_invokes_recorder_and_writes_output(monkeypatch, tmp_path: Path) -> None:
    flame_out = tmp_path / "flame.speedscope.json"
    seen_cmd: list[str] = []

    class _FakeProc:
        def __init__(self, cmd: list[str]) -> None:
            self._cmd = cmd
            self.returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

        def send_signal(self, _sig: int) -> None:
            flame_out.write_text("{}", encoding="utf-8")
            self.returncode = 0

        def terminate(self) -> None:
            self.send_signal(0)

        def communicate(self, timeout: float | None = None) -> tuple[str, str]:
            _ = timeout
            if self.returncode is None:
                self.returncode = 0
            return "", ""

    def _fake_popen(cmd: list[str], **_kwargs):
        seen_cmd[:] = cmd
        return _FakeProc(cmd)

    monkeypatch.setattr("crimson.sim.driver.replay_benchmark.subprocess.Popen", _fake_popen)

    def _run() -> _RenderOnceResult:
        return _RenderOnceResult(run_result=_dummy_run_result())

    result = _run_with_pyspy(
        run_fn=_run,
        flame_out=flame_out,
        flame_format="speedscope",
        pyspy_rate=77,
        pyspy_bin=Path("/tmp/py-spy"),
    )

    assert result.run_result.ticks == 1
    assert flame_out.is_file()
    assert seen_cmd[:2] == ["/tmp/py-spy", "record"]
    assert "--pid" in seen_cmd
    assert str(os.getpid()) in seen_cmd
    assert "--rate" in seen_cmd
    assert "77" in seen_cmd


def test_run_with_pyspy_raises_when_output_missing(monkeypatch, tmp_path: Path) -> None:
    flame_out = tmp_path / "missing.speedscope.json"

    class _FakeProc:
        returncode = None

        def poll(self) -> int | None:
            return self.returncode

        def send_signal(self, _sig: int) -> None:
            self.returncode = 0

        def terminate(self) -> None:
            self.returncode = 0

        def communicate(self, timeout: float | None = None) -> tuple[str, str]:
            _ = timeout
            if self.returncode is None:
                self.returncode = 0
            return "", ""

    monkeypatch.setattr(
        "crimson.sim.driver.replay_benchmark.subprocess.Popen",
        lambda *args, **kwargs: _FakeProc(),
    )

    with pytest.raises(ReplayBenchmarkError, match="did not produce flame artifact"):
        _run_with_pyspy(
            run_fn=lambda: _RenderOnceResult(run_result=_dummy_run_result()),
            flame_out=flame_out,
            flame_format="speedscope",
            pyspy_rate=100,
            pyspy_bin=None,
        )
