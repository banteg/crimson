from __future__ import annotations

from typing import cast

import grim.music as music
from grim.raylib_api import rl


def _music_stub() -> rl.Music:
    return cast("rl.Music", object())


def test_play_music_does_not_unmute_track_mid_fade(mocker) -> None:
    state = music.init_music_state(ready=True, enabled=True, volume=1.0)
    track = _music_stub()
    state.tracks["crimson_theme"] = track
    state.playbacks["crimson_theme"] = music.TrackPlayback(music=track, volume=0.6, muted=True)

    play_music_stream = mocker.patch.object(music.rl, "play_music_stream")
    set_music_volume = mocker.patch.object(music.rl, "set_music_volume")

    music.play_music(state, "crimson_theme")

    playback = state.playbacks["crimson_theme"]
    assert playback.muted is True
    assert playback.volume == 0.6
    assert state.active_track == "crimson_theme"
    play_music_stream.assert_not_called()
    set_music_volume.assert_not_called()


def test_play_music_starts_silent_track_and_mutes_other_active_tracks(mocker) -> None:
    state = music.init_music_state(ready=True, enabled=True, volume=0.8)
    theme = _music_stub()
    game_tune = _music_stub()
    state.tracks["crimson_theme"] = theme
    state.tracks["gt1_ingame"] = game_tune
    state.playbacks["crimson_theme"] = music.TrackPlayback(music=theme, volume=0.0, muted=True)
    state.playbacks["gt1_ingame"] = music.TrackPlayback(music=game_tune, volume=0.7, muted=False)

    play_music_stream = mocker.patch.object(music.rl, "play_music_stream")
    set_music_volume = mocker.patch.object(music.rl, "set_music_volume")

    music.play_music(state, "crimson_theme")

    theme_pb = state.playbacks["crimson_theme"]
    game_pb = state.playbacks["gt1_ingame"]
    assert theme_pb.muted is False
    assert theme_pb.volume == 0.8
    assert game_pb.muted is True
    assert state.active_track == "crimson_theme"
    play_music_stream.assert_called_once_with(theme)
    set_music_volume.assert_called_once_with(theme, 0.8)
