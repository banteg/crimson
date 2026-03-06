from __future__ import annotations

from typing import Any, cast

from crimson.render.world.profile_hooks import profile_pass
from crimson.replay.driver.render_telemetry import RenderTelemetrySession
from crimson.replay.driver.replay_benchmark import (
    BenchmarkAggregate,
    ReplayRenderTelemetryFrame,
    _summarize_render_telemetry,
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
