from __future__ import annotations

from crimson.replay.driver.replay_render import (
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


def test_infer_effective_capture_sample_rate_returns_derived_rate() -> None:
    assert _infer_effective_capture_sample_rate(captured_frames=220_500, captured_ticks=300, replay_tick_rate=60) == 44_100
