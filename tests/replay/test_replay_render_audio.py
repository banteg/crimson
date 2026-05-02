from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from crimson.replay.driver.replay_render import (
    ReplayRenderError,
    _build_audio_sync_filter,
    _infer_effective_capture_sample_rate,
)


def test_build_audio_sync_filter_exact_match() -> None:
    assert _build_audio_sync_filter(captured_frames=96_000, target_frames=96_000) == "asetpts=N/SR/TB"


def test_build_audio_sync_filter_trim_when_captured_longer() -> None:
    assert _build_audio_sync_filter(captured_frames=100_000, target_frames=90_000) == "atrim=end_sample=90000,asetpts=N/SR/TB"


def test_build_audio_sync_filter_pad_when_captured_shorter() -> None:
    assert (
        _build_audio_sync_filter(captured_frames=90_000, target_frames=100_000)
        == "apad=pad_len=10000,atrim=end_sample=100000,asetpts=N/SR/TB"
    )


def test_build_audio_sync_filter_rejects_invalid_counts() -> None:
    with pytest.raises(ReplayRenderError, match="captured_frames > 0"):
        _build_audio_sync_filter(captured_frames=0, target_frames=1)
    with pytest.raises(ReplayRenderError, match="target_frames > 0"):
        _build_audio_sync_filter(captured_frames=1, target_frames=0)


def test_infer_effective_capture_sample_rate_returns_derived_rate() -> None:
    assert _infer_effective_capture_sample_rate(captured_frames=220_500, captured_ticks=300, replay_tick_rate=60) == 44_100


def test_infer_effective_capture_sample_rate_rejects_out_of_range() -> None:
    with pytest.raises(ReplayRenderError, match="out of range"):
        _infer_effective_capture_sample_rate(captured_frames=10_000_000, captured_ticks=1, replay_tick_rate=60)


def test_capture_audio_track_reports_progress_without_manual_fx_queue_clears(mocker, tmp_path: Path) -> None:
    import crimson.modes.replay_playback_mode as replay_playback_mode_mod
    import crimson.replay.driver.replay_render as replay_render_mod

    class _FakeMode:
        def __init__(self, *_args, **_kwargs) -> None:
            self.finished = False
            self.close_requested = False
            self.tick_index = 0
            self._runtime = SimpleNamespace(render_resources=SimpleNamespace())

        def open(self) -> None:
            return

        def update(self, _dt: float) -> None:
            self.tick_index += 1
            if self.tick_index >= 3:
                self.finished = True

        def close(self) -> None:
            return

    mocker.patch.object(replay_playback_mode_mod, "ReplayPlaybackMode", _FakeMode)

    class _FakeCapture:
        def __init__(self, *, rl, output_path: Path, sample_rate: int, channels: int) -> None:
            self.sample_rate = int(sample_rate)
            self.channels = int(channels)
            self.captured_frames = 2400

        def start(self) -> None:
            return

        def flush_pending(self) -> None:
            return

        def stop(self) -> None:
            return

        def close(self) -> None:
            return

    mocker.patch.object(replay_render_mod, "_MixedAudioCapture", _FakeCapture)
    mocker.patch.object(replay_render_mod.time, "sleep", side_effect=lambda _seconds: None)

    class _FakeRl:
        def __init__(self) -> None:
            self._master = 1.0

        def get_master_volume(self) -> float:
            return float(self._master)

        def set_master_volume(self, value: float) -> None:
            self._master = float(value)

    class _FakeConfig:
        def __init__(self) -> None:
            self.audio = SimpleNamespace(sound_disabled=False, music_disabled=False)

    class _Progress(replay_render_mod.ReplayRenderProgress):
        events: list[tuple[str, int, int, int]]

        def update(
            self,
            *,
            phase: replay_render_mod.ReplayRenderPhase,
            frame_count: int,
            tick_index: int,
            total_ticks: int,
        ) -> None:
            self.events.append((phase, int(frame_count), int(tick_index), int(total_ticks)))

    progress = _Progress(events=[])

    captured = replay_render_mod._capture_replay_audio_track(
        rl=_FakeRl(),
        ctx=object(),
        replay_path=Path("dummy.crd"),
        config=_FakeConfig(),
        console=object(),
        max_ticks=None,
        trace_rng=False,
        output_path=tmp_path / "audio.raw",
        replay_tick_rate=60,
        progress=progress,
        total_ticks=120,
    )

    assert captured.sample_rate == 48_000
    assert captured.effective_sample_rate == 48_000
    assert captured.channels == 2
    assert captured.captured_frames == 2400
    assert captured.captured_ticks == 3
    assert progress.events == [
        ("audio", 0, 1, 120),
        ("audio", 0, 2, 120),
        ("audio", 0, 3, 120),
    ]


def test_mux_raw_audio_with_video_uses_output_safety_and_sync_filter_without_time_warp(mocker, tmp_path: Path) -> None:
    import crimson.replay.driver.replay_render as replay_render_mod

    video_path = tmp_path / "video.mp4"
    audio_path = tmp_path / "audio.f32le"
    output_path = tmp_path / "out.mp4"
    ffmpeg_path = tmp_path / "ffmpeg"
    video_path.write_bytes(b"video")
    audio_path.write_bytes(b"audio")
    ffmpeg_path.write_text("", encoding="utf-8")
    run = mocker.patch.object(
        replay_render_mod.subprocess,
        "run",
        return_value=SimpleNamespace(returncode=0, stderr=b""),
    )

    replay_render_mod._mux_raw_audio_with_video(
        ffmpeg_path=ffmpeg_path,
        video_path=video_path,
        audio_path=audio_path,
        output_path=output_path,
        overwrite=True,
        audio_sample_rate=48_000,
        audio_channels=2,
        captured_audio_frames=100_000,
        target_audio_frames=90_000,
    )

    run.assert_called_once()
    captured_cmd = cast("list[str]", run.call_args.args[0])
    af_index = captured_cmd.index("-af")
    audio_filter = captured_cmd[af_index + 1]
    assert (
        audio_filter
        == "asoftclip=type=atan:threshold=1:output=1,volume=-1dB,atrim=end_sample=90000,asetpts=N/SR/TB"
    )
    assert "atempo" not in audio_filter
    assert "alimiter" not in audio_filter
