from __future__ import annotations

import pytest

from grim import sfx
from grim.audio_math import native_sound_gain, native_sound_pan, raylib_pan
from grim.geom import Vec2
from grim.sfx_map import SfxId
from tests.support.audio import make_sfx_state, stub_sfx_backend


@pytest.mark.parametrize(
    "sfx_id, cooldown", [(SfxId.PISTOL_FIRE, 0.05), (SfxId.FLAMER_FIRE_01, 0.44), (SfxId.FLAMER_FIRE_02, 0.44)],
)
def test_per_id_cooldown_blocks_before_pitch_or_voice_changes(mocker, sfx_id, cooldown) -> None:
    backend = stub_sfx_backend(mocker)
    state = make_sfx_state(sfx_id)
    sfx.play_sfx(state, sfx_id, reflex_boost_timer=2.0, pan=425, gain=0.8)
    first_start = list(backend.mock_calls)

    sfx.update_sfx(state, cooldown / 2)
    sfx.play_sfx(state, sfx_id, reflex_boost_timer=0.0)
    assert backend.mock_calls == first_start
    assert state.rate_scale_hz == 22050

    sfx.update_sfx(state, cooldown)
    residue = state.cooldowns[sfx_id]
    assert residue < 0.0
    sfx.update_sfx(state, 1.0)
    assert state.cooldowns[sfx_id] == residue
    sfx.play_sfx(state, sfx_id)
    assert backend.play_sound.call_count == 2
    assert state.rate_scale_hz == 44100
    # Reusing a previously panned voice for a centered request resets pan/gain.
    assert backend.set_sound_pan.call_args.args[1] == 0.5
    assert state.sample(sfx_id).source.gain == 1.0


def test_sound_ids_sharing_an_asset_have_independent_cooldowns(mocker) -> None:
    backend = stub_sfx_backend(mocker)
    state = make_sfx_state(SfxId.SHOCK_FIRE, SfxId.SHOCK_FIRE_ALT)
    assert state.sample(SfxId.SHOCK_FIRE) is state.sample(SfxId.SHOCK_FIRE_ALT)

    for _ in range(3):
        sfx.play_sfx(state, SfxId.SHOCK_FIRE)
        sfx.play_sfx(state, SfxId.SHOCK_FIRE_ALT)

    assert backend.play_sound.call_count == 2
    assert len(state.cooldowns) == 2


def test_volume_change_retains_each_active_voice_gain_and_pan(mocker) -> None:
    backend = stub_sfx_backend(mocker)
    state = make_sfx_state(SfxId.PISTOL_FIRE)
    sample = state.sample(SfxId.PISTOL_FIRE)
    sample.aliases.append(sfx.SfxVoice(sfx.rl.Sound()))
    sfx.play_sfx(state, SfxId.PISTOL_FIRE, pan=-425, gain=0.8)
    mocker.patch.object(sfx.rl, "is_sound_playing", side_effect=lambda sound: sound is sample.source.sound)
    sfx.update_sfx(state, 0.1)
    sfx.play_sfx(state, SfxId.PISTOL_FIRE, pan=850, gain=0.7)
    pans = list(backend.set_sound_pan.call_args_list)

    sfx.set_sfx_volume(state, 0.5)

    levels = [entry.args[1] for entry in backend.set_sound_volume.call_args_list[-2:]]
    assert levels == pytest.approx(
        [
            native_sound_gain(0.4) * raylib_pan(-425)[1],
            native_sound_gain(0.35) * raylib_pan(850)[1],
        ],
    )
    assert backend.set_sound_pan.call_args_list == pans
    sfx.set_sfx_volume(state, 0.0)
    assert [entry.args[1] for entry in backend.set_sound_volume.call_args_list[-2:]] == [0.0, 0.0]


@pytest.mark.parametrize("pan_db", [-10_000, -850, -425, 0, 425, 850, 10_000])
def test_channel_levels_match_directsound_attenuation(pan_db) -> None:
    pan, compensation = raylib_pan(pan_db)
    # Independent reconstruction of raylib 5.5 MixAudioFrames at master gain 1.
    left = compensation * (3 * pan - pan**3) / 2
    right = compensation * (3 * (1 - pan) - (1 - pan) ** 3) / 2
    quiet = 10 ** (-abs(pan_db) / 2000)
    expected = (1, quiet) if pan_db < 0 else (quiet, 1)
    assert (left, right) == pytest.approx(expected, abs=3e-8)


@pytest.mark.parametrize(
    "position, camera, width, expected",
    [
        (None, Vec2(123, 0), 640, 0),
        (Vec2(256, 0), Vec2(), 1024, -425),
        (Vec2(768, 0), Vec2(), 1024, 425),
        (Vec2(768, 0), Vec2(-448, 0), 640, 0),
        (Vec2(-100_000, 0), Vec2(), 1024, -10_000),
        (Vec2(100_000, 0), Vec2(), 1024, 10_000),
    ],
)
def test_native_pan_uses_camera_and_viewport(position, camera, width, expected) -> None:
    assert native_sound_pan(position, camera=camera, screen_width=width) == expected


@pytest.mark.parametrize("volume, hundredths_db", [(1.0, 0), (0.7, -999), (0.4, -1999), (0.1, -3000)])
def test_native_positive_volume_curve(volume, hundredths_db) -> None:
    # f32 intermediates followed by __ftol: the first two nonzero values
    # approach their integer dB boundary from above and truncate toward zero.
    assert native_sound_gain(volume) == pytest.approx(10 ** (hundredths_db / 2000))
