from __future__ import annotations

import grim.music as music


def test_play_music_does_not_unmute_track_mid_fade(monkeypatch) -> None:
    state = music.init_music_state(ready=True, enabled=True, volume=1.0)
    track = object()
    state.tracks["crimson_theme"] = track
    state.playbacks["crimson_theme"] = music.TrackPlayback(music=track, volume=0.6, muted=True)

    play_calls: list[object] = []
    set_calls: list[tuple[object, float]] = []
    monkeypatch.setattr(music.rl, "play_music_stream", lambda m: play_calls.append(m))
    monkeypatch.setattr(music.rl, "set_music_volume", lambda m, v: set_calls.append((m, float(v))))

    music.play_music(state, "crimson_theme")

    playback = state.playbacks["crimson_theme"]
    assert playback.muted is True
    assert playback.volume == 0.6
    assert state.active_track == "crimson_theme"
    assert play_calls == []
    assert set_calls == []


def test_play_music_starts_silent_track_and_mutes_other_active_tracks(monkeypatch) -> None:
    state = music.init_music_state(ready=True, enabled=True, volume=0.8)
    theme = object()
    game_tune = object()
    state.tracks["crimson_theme"] = theme
    state.tracks["gt1_ingame"] = game_tune
    state.playbacks["crimson_theme"] = music.TrackPlayback(music=theme, volume=0.0, muted=True)
    state.playbacks["gt1_ingame"] = music.TrackPlayback(music=game_tune, volume=0.7, muted=False)

    play_calls: list[object] = []
    set_calls: list[tuple[object, float]] = []
    monkeypatch.setattr(music.rl, "play_music_stream", lambda m: play_calls.append(m))
    monkeypatch.setattr(music.rl, "set_music_volume", lambda m, v: set_calls.append((m, float(v))))

    music.play_music(state, "crimson_theme")

    theme_pb = state.playbacks["crimson_theme"]
    game_pb = state.playbacks["gt1_ingame"]
    assert theme_pb.muted is False
    assert theme_pb.volume == 0.8
    assert game_pb.muted is True
    assert state.active_track == "crimson_theme"
    assert play_calls == [theme]
    assert set_calls == [(theme, 0.8)]
