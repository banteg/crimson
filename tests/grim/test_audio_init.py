from __future__ import annotations

import grim.audio as grim_audio


def test_init_audio_state_preloads_sfx_before_music(mocker, make_game_state) -> None:
    game_state = make_game_state()
    mocker.patch.object(grim_audio.rl, "is_audio_device_ready", return_value=True)
    load_sfx_index = mocker.patch.object(grim_audio.sfx, "load_sfx_index")
    preload_sfx_samples = mocker.patch.object(grim_audio.sfx, "preload_sfx_samples")
    load_music_tracks = mocker.patch.object(grim_audio.music, "load_music_tracks")
    call_order = mocker.Mock()
    call_order.attach_mock(load_sfx_index, "load_sfx_index")
    call_order.attach_mock(preload_sfx_samples, "preload_sfx_samples")
    call_order.attach_mock(load_music_tracks, "load_music_tracks")

    state = grim_audio.init_audio_state(game_state.config, game_state.assets_dir, game_state.console)

    assert state.ready is True
    assert call_order.mock_calls == [
        mocker.call.load_sfx_index(state.sfx, game_state.assets_dir, game_state.console),
        mocker.call.preload_sfx_samples(state.sfx, game_state.console),
        mocker.call.load_music_tracks(state.music, game_state.assets_dir, game_state.console),
    ]
