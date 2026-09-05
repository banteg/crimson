from __future__ import annotations

import grim.sfx as grim_sfx
from grim.sfx_map import SfxId
from tests.support.helpers import assert_float_close


def test_play_sfx_applies_native_reflex_rate_scaling(mocker) -> None:
    state = grim_sfx.init_sfx_state(ready=True, enabled=True, volume=1.0)

    voice = grim_sfx.SfxVoice(grim_sfx.rl.Sound())
    sample = grim_sfx.SfxSample("pistol.ogg", source=voice, aliases=[])
    state.samples[SfxId.PISTOL_FIRE] = sample

    set_sound_pitch = mocker.patch.object(grim_sfx.rl, "set_sound_pitch", create=True)
    mocker.patch.object(grim_sfx.rl, "play_sound")
    mocker.patch.object(grim_sfx.rl, "is_sound_playing", return_value=False)
    mocker.patch.object(grim_sfx.rl, "set_sound_pan")
    mocker.patch.object(grim_sfx.rl, "set_sound_volume")

    grim_sfx.play_sfx(state, SfxId.PISTOL_FIRE, reflex_boost_timer=0.0)
    assert state.rate_scale_hz == 44100
    assert_float_close(float(set_sound_pitch.call_args_list[-1].args[1]), 1.0)

    grim_sfx.update_sfx(state, 0.5)
    grim_sfx.play_sfx(state, SfxId.PISTOL_FIRE, reflex_boost_timer=2.0)
    assert state.rate_scale_hz == 22050
    assert_float_close(float(set_sound_pitch.call_args_list[-1].args[1]), 0.5)

    grim_sfx.update_sfx(state, 0.5)
    grim_sfx.play_sfx(state, SfxId.PISTOL_FIRE, reflex_boost_timer=1.0)
    assert state.rate_scale_hz == 22050
    assert_float_close(float(set_sound_pitch.call_args_list[-1].args[1]), 0.5)

    grim_sfx.update_sfx(state, 0.5)
    grim_sfx.play_sfx(state, SfxId.PISTOL_FIRE, reflex_boost_timer=0.25)
    assert state.rate_scale_hz == 38587
    assert_float_close(
        float(set_sound_pitch.call_args_list[-1].args[1]),
        grim_sfx._pitch_scale_from_rate_hz(38587),
    )

    grim_sfx.update_sfx(state, 0.5)
    grim_sfx.play_sfx(state, SfxId.PISTOL_FIRE, reflex_boost_timer=-0.1)
    assert state.rate_scale_hz == 44100
    assert_float_close(float(set_sound_pitch.call_args_list[-1].args[1]), 1.0)
