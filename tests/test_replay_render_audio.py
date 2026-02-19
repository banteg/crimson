from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from crimson.sim.driver.replay_render import ReplayRenderError, _build_atempo_filters


def test_build_atempo_filters_identity_tempo_returns_empty() -> None:
    assert _build_atempo_filters(1.0) == []


def test_build_atempo_filters_splits_large_tempo() -> None:
    assert _build_atempo_filters(3.0) == ["atempo=2.000000000", "atempo=1.500000000"]


def test_build_atempo_filters_splits_small_tempo() -> None:
    assert _build_atempo_filters(0.125) == [
        "atempo=0.500000000",
        "atempo=0.500000000",
        "atempo=0.500000000",
    ]


def test_build_atempo_filters_rejects_invalid_tempo() -> None:
    with pytest.raises(ReplayRenderError, match="invalid audio tempo factor"):
        _build_atempo_filters(0.0)


def test_capture_audio_track_clears_fx_queues_and_reports_progress(monkeypatch, tmp_path: Path) -> None:
    import crimson.modes.replay_playback_mode as replay_playback_mode_mod
    import crimson.sim.driver.replay_render as replay_render_mod

    class _Queue:
        def __init__(self) -> None:
            self.clear_calls = 0

        def clear(self) -> None:
            self.clear_calls += 1

    fx_queue = _Queue()
    fx_queue_rotated = _Queue()

    class _FakeMode:
        def __init__(self, *_args, **_kwargs) -> None:
            self.finished = False
            self.close_requested = False
            self.tick_index = 0
            self._world = SimpleNamespace(fx_queue=fx_queue, fx_queue_rotated=fx_queue_rotated)

        def open(self) -> None:
            return

        def update(self, _dt: float) -> None:
            self.tick_index += 1
            if self.tick_index >= 3:
                self.finished = True

        def close(self) -> None:
            return

    monkeypatch.setattr(replay_playback_mode_mod, "ReplayPlaybackMode", _FakeMode)

    class _FakeCapture:
        def __init__(self, *, rl, output_path: Path, sample_rate: int, channels: int) -> None:
            self.sample_rate = int(sample_rate)
            self.channels = int(channels)
            self.captured_frames = 1440

        def start(self) -> None:
            return

        def flush_pending(self) -> None:
            return

        def stop(self) -> None:
            return

        def close(self) -> None:
            return

    monkeypatch.setattr(replay_render_mod, "_MixedAudioCapture", _FakeCapture)
    monkeypatch.setattr(replay_render_mod.time, "sleep", lambda _seconds: None)

    class _FakeRl:
        def __init__(self) -> None:
            self._master = 1.0

        def get_master_volume(self) -> float:
            return float(self._master)

        def set_master_volume(self, value: float) -> None:
            self._master = float(value)

    class _FakeConfig:
        def set_bool_value(self, _key: str, _value: bool) -> None:
            return

    progress_calls: list[tuple[int, int, int]] = []

    def _progress(frame_count: int, tick_index: int, total_ticks: int) -> None:
        progress_calls.append((int(frame_count), int(tick_index), int(total_ticks)))

    captured = replay_render_mod._capture_replay_audio_track(
        rl=_FakeRl(),
        ctx=object(),
        replay_path=Path("dummy.crd"),
        config=_FakeConfig(),
        console=object(),
        max_ticks=None,
        strict_events=True,
        trace_rng=False,
        output_path=tmp_path / "audio.raw",
        replay_tick_rate=60,
        progress=_progress,
        progress_frame_count=120,
        progress_tick_offset=120,
        progress_total_ticks=240,
    )

    assert captured.sample_rate == 48_000
    assert captured.channels == 2
    assert captured.captured_frames == 1440
    assert fx_queue.clear_calls == 3
    assert fx_queue_rotated.clear_calls == 3
    assert progress_calls == [
        (120, 121, 240),
        (120, 122, 240),
        (120, 123, 240),
    ]
