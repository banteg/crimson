from __future__ import annotations

from typing import Any, cast

import grim.sfx as grim_sfx
from grim.sfx_map import SfxId
from tests.support.helpers import assert_float_close


class _FakeSample:
    def __init__(self, voice: object) -> None:
        self._voice = voice

    def acquire_voice(self) -> object:
        return self._voice


def test_play_sfx_applies_native_reflex_rate_scaling(mocker) -> None:
    state = grim_sfx.init_sfx_state(ready=True, enabled=True, volume=1.0)

    voice = object()
    sample = _FakeSample(voice)
    state.samples[SfxId.PISTOL_FIRE] = cast(Any, sample)

    set_sound_pitch = mocker.patch.object(grim_sfx.rl, "set_sound_pitch", create=True)
    mocker.patch.object(grim_sfx.rl, "play_sound")

    grim_sfx.play_sfx(state, SfxId.PISTOL_FIRE, reflex_boost_timer=0.0)
    assert state.rate_scale_hz == 44100
    assert_float_close(float(set_sound_pitch.call_args_list[-1].args[1]), 1.0)

    grim_sfx.play_sfx(state, SfxId.PISTOL_FIRE, reflex_boost_timer=2.0)
    assert state.rate_scale_hz == 22050
    assert_float_close(float(set_sound_pitch.call_args_list[-1].args[1]), 0.5)

    grim_sfx.play_sfx(state, SfxId.PISTOL_FIRE, reflex_boost_timer=1.0)
    assert state.rate_scale_hz == 22050
    assert_float_close(float(set_sound_pitch.call_args_list[-1].args[1]), 0.5)

    grim_sfx.play_sfx(state, SfxId.PISTOL_FIRE, reflex_boost_timer=0.25)
    assert state.rate_scale_hz == 38588
    assert_float_close(
        float(set_sound_pitch.call_args_list[-1].args[1]),
        grim_sfx._pitch_scale_from_rate_hz(38588),
    )

    grim_sfx.play_sfx(state, SfxId.PISTOL_FIRE, reflex_boost_timer=-0.1)
    assert state.rate_scale_hz == 44100
    assert_float_close(float(set_sound_pitch.call_args_list[-1].args[1]), 1.0)
