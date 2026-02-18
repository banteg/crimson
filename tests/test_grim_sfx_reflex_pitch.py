from __future__ import annotations

import pytest

import grim.sfx as grim_sfx


class _FakeSample:
    def __init__(self, voice: object) -> None:
        self._voice = voice

    def acquire_voice(self) -> object:
        return self._voice


def test_play_sfx_applies_native_reflex_rate_scaling(monkeypatch: pytest.MonkeyPatch) -> None:
    state = grim_sfx.init_sfx_state(ready=True, enabled=True, volume=1.0)
    state.key_to_entry["sfx_test"] = "test.ogg"

    voice = object()
    sample = _FakeSample(voice)
    monkeypatch.setattr(grim_sfx, "_load_sample", lambda _state, _key: sample)

    pitches: list[float] = []
    monkeypatch.setattr(grim_sfx.rl, "set_sound_pitch", lambda _voice, pitch: pitches.append(float(pitch)), raising=False)
    monkeypatch.setattr(grim_sfx.rl, "play_sound", lambda _voice: None)

    grim_sfx.play_sfx(state, "sfx_test", allow_variants=False, reflex_boost_timer=0.0)
    assert state.rate_scale_hz == 44100
    assert pitches[-1] == pytest.approx(1.0, abs=1e-6)

    grim_sfx.play_sfx(state, "sfx_test", allow_variants=False, reflex_boost_timer=2.0)
    assert state.rate_scale_hz == 22050
    assert pitches[-1] == pytest.approx(0.5, abs=1e-6)

    grim_sfx.play_sfx(state, "sfx_test", allow_variants=False, reflex_boost_timer=1.0)
    assert state.rate_scale_hz == 22050
    assert pitches[-1] == pytest.approx(0.5, abs=1e-6)

    grim_sfx.play_sfx(state, "sfx_test", allow_variants=False, reflex_boost_timer=0.25)
    assert state.rate_scale_hz == 38588
    assert pitches[-1] == pytest.approx(38588 / 44100, abs=1e-6)

    grim_sfx.play_sfx(state, "sfx_test", allow_variants=False, reflex_boost_timer=-0.1)
    assert state.rate_scale_hz == 44100
    assert pitches[-1] == pytest.approx(1.0, abs=1e-6)
