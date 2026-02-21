from __future__ import annotations

import grim.sfx as grim_sfx
from tests.helpers import assert_float_close


class _FakeSample:
    def __init__(self, voice: object) -> None:
        self._voice = voice

    def acquire_voice(self) -> object:
        return self._voice


def test_play_sfx_applies_native_reflex_rate_scaling(mocker) -> None:
    state = grim_sfx.init_sfx_state(ready=True, enabled=True, volume=1.0)
    state.key_to_entry["sfx_test"] = "test.ogg"

    voice = object()
    sample = _FakeSample(voice)
    mocker.patch.object(grim_sfx, "_load_sample", side_effect=lambda _state, _key: sample)

    set_sound_pitch = mocker.patch.object(grim_sfx.rl, "set_sound_pitch", create=True)
    mocker.patch.object(grim_sfx.rl, "play_sound")

    grim_sfx.play_sfx(state, "sfx_test", allow_variants=False, reflex_boost_timer=0.0)
    assert state.rate_scale_hz == 44100
    assert_float_close(float(set_sound_pitch.call_args_list[-1].args[1]), 1.0)

    grim_sfx.play_sfx(state, "sfx_test", allow_variants=False, reflex_boost_timer=2.0)
    assert state.rate_scale_hz == 22050
    assert_float_close(float(set_sound_pitch.call_args_list[-1].args[1]), 0.5)

    grim_sfx.play_sfx(state, "sfx_test", allow_variants=False, reflex_boost_timer=1.0)
    assert state.rate_scale_hz == 22050
    assert_float_close(float(set_sound_pitch.call_args_list[-1].args[1]), 0.5)

    grim_sfx.play_sfx(state, "sfx_test", allow_variants=False, reflex_boost_timer=0.25)
    assert state.rate_scale_hz == 38588
    assert_float_close(
        float(set_sound_pitch.call_args_list[-1].args[1]),
        grim_sfx._pitch_scale_from_rate_hz(38588),
    )

    grim_sfx.play_sfx(state, "sfx_test", allow_variants=False, reflex_boost_timer=-0.1)
    assert state.rate_scale_hz == 44100
    assert_float_close(float(set_sound_pitch.call_args_list[-1].args[1]), 1.0)
