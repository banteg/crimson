from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from grim import music
from grim import paq as grim_paq
from grim.rand import Crand
from grim.raylib_api import rl


def _music_stub() -> rl.Music:
    return cast("rl.Music", object())


def test_play_music_does_not_unmute_track_mid_fade(mocker) -> None:
    state = music.init_music_state(ready=True, enabled=True, volume=1.0)
    track = _music_stub()
    state.tracks["crimson_theme"] = music.MusicTrack(stream=track, track_id=0, volume=0.6, muted=True)

    play_music_stream = mocker.patch.object(music.rl, "play_music_stream")
    set_music_volume = mocker.patch.object(music.rl, "set_music_volume")

    music.play_music(state, "crimson_theme")

    playback = state.tracks["crimson_theme"]
    assert playback.muted is True
    assert playback.volume == 0.6
    assert state.active_track == "crimson_theme"
    play_music_stream.assert_not_called()
    set_music_volume.assert_not_called()


def test_play_music_starts_silent_track_and_mutes_other_active_tracks(mocker) -> None:
    state = music.init_music_state(ready=True, enabled=True, volume=0.8)
    theme = _music_stub()
    game_tune = _music_stub()
    state.tracks["crimson_theme"] = music.MusicTrack(stream=theme, track_id=0, volume=0.0, muted=True)
    state.tracks["gt1_ingame"] = music.MusicTrack(stream=game_tune, track_id=0, volume=0.7, muted=False)

    play_music_stream = mocker.patch.object(music.rl, "play_music_stream")
    mocker.patch.object(music.rl, "stop_music_stream")
    set_music_volume = mocker.patch.object(music.rl, "set_music_volume")

    music.play_music(state, "crimson_theme")

    theme_pb = state.tracks["crimson_theme"]
    game_pb = state.tracks["gt1_ingame"]
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
    mocker.patch.object(music.rl, "is_music_valid", return_value=True)
    load_music_stream_from_memory = mocker.patch.object(music.rl, "load_music_stream_from_memory")
    set_music_volume = mocker.patch.object(music.rl, "set_music_volume")

    result = music.load_music_track(state, tmp_path, "music/custom.ogg")

    assert result == ("custom", 0)
    assert state.tracks["custom"].stream is track
    assert state.tracks["custom"].track_id == 0
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
    mocker.patch.object(music.rl, "is_music_valid", return_value=True)
    load_music_stream_from_memory = mocker.patch.object(
        music.rl,
        "load_music_stream_from_memory",
        return_value=track,
    )
    set_music_volume = mocker.patch.object(music.rl, "set_music_volume")

    result = music.load_music_track(state, tmp_path, "music/custom.ogg")

    assert result == ("custom", 0)
    assert state.tracks["custom"].stream is track
    assert state.tracks["custom"].track_id == 0
    assert state.next_track_id == 1
    assert state.paq_entries == {"music/custom.ogg": payload}
    load_music_stream.assert_not_called()
    load_music_stream_from_memory.assert_called_once_with(".ogg", payload, len(payload))
    set_music_volume.assert_called_once_with(track, 0.4)


@pytest.fixture
def music_backend(mocker):
    playing: set[object] = set()
    mocker.patch.object(rl, "play_music_stream", side_effect=playing.add)
    mocker.patch.object(rl, "resume_music_stream", side_effect=playing.add)
    mocker.patch.object(rl, "pause_music_stream", side_effect=playing.discard)
    mocker.patch.object(rl, "stop_music_stream", side_effect=playing.discard)
    mocker.patch.object(rl, "is_music_stream_playing", side_effect=lambda stream: stream in playing)
    mocker.patch.object(rl, "update_music_stream")
    mocker.patch.object(rl, "set_music_volume")
    return playing


@pytest.mark.parametrize("initial_volume", [0.0, 0.8])
def test_volume_restore_resumes_selected_tune_without_another_random_pick(music_backend, initial_volume) -> None:
    state = music.init_music_state(ready=True, enabled=True, volume=initial_volume)
    track = music.MusicTrack(stream=_music_stub(), track_id=0)
    state.tracks["game"] = track
    music.queue_track(state, "game")
    rng = Crand(1)
    assert music.trigger_game_tune(state, rng=rng) == "game"
    rng_after_selection = rng.state
    music.set_music_volume(state, 0.0)
    music.update_music(state, 0.1)
    assert track.stream not in music_backend
    assert not track.muted
    music.set_music_volume(state, 0.8)
    for _ in range(10):
        music.update_music(state, 0.1)
    assert track.stream in music_backend
    assert track.volume == 0.8
    assert state.active_track == "game"
    assert music.trigger_game_tune(state, rng=rng) is None
    assert rng.state == rng_after_selection


def test_muted_track_does_not_resume_after_volume_restore(music_backend) -> None:
    state = music.init_music_state(ready=True, enabled=True, volume=0.8)
    track = music.MusicTrack(stream=_music_stub(), track_id=0)
    state.tracks["theme"] = track
    music.play_music(state, "theme")
    music.stop_music(state)
    music.set_music_volume(state, 0.0)
    music.update_music(state, 0.1)
    music.set_music_volume(state, 0.8)
    music.update_music(state, 0.1)
    assert track.muted
    assert track.stream not in music_backend


def test_repeated_result_request_waits_for_old_fade_then_starts(music_backend) -> None:
    state = music.init_music_state(ready=True, enabled=True, volume=0.8)
    result = music.MusicTrack(stream=_music_stub(), track_id=0, volume=0.1)
    game = music.MusicTrack(stream=_music_stub(), track_id=1, volume=0.8, muted=False)
    state.tracks.update(shortie_monk=result, game=game)
    music_backend.update((result.stream, game.stream))
    music.play_music(state, "shortie_monk")
    assert result.muted and game.muted
    for _ in range(3):
        music.update_music(state, 0.1)
        music.play_music(state, "shortie_monk")
    assert not result.muted and game.muted
    assert result.stream in music_backend


def test_quest_completion_starts_at_silence_and_fades_in(music_backend, mocker) -> None:
    state = music.init_music_state(ready=True, enabled=True, volume=0.8)
    track = music.MusicTrack(stream=_music_stub(), track_id=0)
    state.tracks["crimsonquest"] = track
    set_volume = mocker.patch.object(rl, "set_music_volume")
    music.play_music(state, "crimsonquest", fade_in=True)
    assert track.volume == 0.0 and not track.muted
    assert all(call.args[1] == 0.0 for call in set_volume.call_args_list)
    music.update_music(state, 0.1)
    assert track.volume == 0.1
