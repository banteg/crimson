from __future__ import annotations

from grim import music as music_module
from grim.music import MusicState, MusicTrack, resume_music
from grim.raylib_api import rl


def test_resume_brings_a_fading_track_back_and_restarts_a_silent_one(mocker) -> None:
    fading = MusicTrack(stream=rl.Music(), track_id=0, muted=True, volume=0.4)
    tune = MusicTrack(stream=rl.Music(), track_id=1, muted=False, volume=1.0)
    state = MusicState(ready=True, enabled=True, volume=1.0, tracks={"theme": fading, "tune": tune}, active_track="tune")

    resume_music(state, "theme")

    assert (fading.muted, fading.volume, tune.muted, state.active_track) == (False, 0.4, True, "theme")
    play_music = mocker.patch.object(music_module, "play_music")
    fading.volume = 0.0
    resume_music(state, "theme")
    play_music.assert_called_once_with(state, "theme")
