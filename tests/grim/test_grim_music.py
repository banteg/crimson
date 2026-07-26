from __future__ import annotations

from pathlib import Path
from typing import cast

from grim import music
from grim import paq as grim_paq
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


def test_load_music_track_loads_unpacked_file_on_demand(mocker, tmp_path: Path) -> None:
    state = music.init_music_state(ready=True, enabled=True, volume=0.4)
    track = _music_stub()
    track_path = tmp_path / "music" / "custom.ogg"
    track_path.parent.mkdir(parents=True, exist_ok=True)
    track_path.write_bytes(b"OggS")

    load_music_stream = mocker.patch.object(music.rl, "load_music_stream", return_value=track)
    load_music_stream_from_memory = mocker.patch.object(music.rl, "load_music_stream_from_memory")
    set_music_volume = mocker.patch.object(music.rl, "set_music_volume")

    result = music.load_music_track(state, tmp_path, "music/custom.ogg")

    assert result == ("custom", 0)
    assert state.tracks["custom"] is track
    assert state.track_ids["custom"] == 0
    assert state.next_track_id == 1
    load_music_stream.assert_called_once_with(str(track_path))
    load_music_stream_from_memory.assert_not_called()
    set_music_volume.assert_called_once_with(track, 0.4)


def test_load_music_track_loads_paq_entry_on_demand(mocker, tmp_path: Path) -> None:
    state = music.init_music_state(ready=True, enabled=True, volume=0.4)
    track = _music_stub()
    payload = b"OggS"
    grim_paq.write_paq(tmp_path / music.MUSIC_PAK_NAME, [("music/custom.ogg", payload)])

    load_music_stream = mocker.patch.object(music.rl, "load_music_stream")
    load_music_stream_from_memory = mocker.patch.object(
        music.rl,
        "load_music_stream_from_memory",
        return_value=track,
    )
    set_music_volume = mocker.patch.object(music.rl, "set_music_volume")

    result = music.load_music_track(state, tmp_path, "music/custom.ogg")

    assert result == ("custom", 0)
    assert state.tracks["custom"] is track
    assert state.track_ids["custom"] == 0
    assert state.next_track_id == 1
    assert state.paq_entries == {"music/custom.ogg": payload}
    load_music_stream.assert_not_called()
    load_music_stream_from_memory.assert_called_once_with(".ogg", payload, len(payload))
    set_music_volume.assert_called_once_with(track, 0.4)
