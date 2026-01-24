from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pyray as rl

from .console import ConsoleState
from . import paq


MUSIC_PAK_NAME = "music.paq"
MUSIC_TRACKS: dict[str, tuple[str, ...]] = {
    "intro": ("music/intro.ogg", "intro.ogg"),
    "shortie_monk": ("music/shortie_monk.ogg", "shortie_monk.ogg"),
    "crimson_theme": ("music/crimson_theme.ogg", "crimson_theme.ogg"),
    "crimsonquest": ("music/crimsonquest.ogg", "crimsonquest.ogg"),
    "gt1_ingame": ("music/gt1_ingame.ogg", "gt1_ingame.ogg"),
    "gt2_harppen": ("music/gt2_harppen.ogg", "gt2_harppen.ogg"),
}


@dataclass(slots=True)
class MusicState:
    ready: bool
    enabled: bool
    volume: float
    tracks: dict[str, rl.Music]
    active_track: str | None


def init_music_state(*, ready: bool, enabled: bool, volume: float) -> MusicState:
    return MusicState(
        ready=ready,
        enabled=enabled,
        volume=float(volume),
        tracks={},
        active_track=None,
    )


def load_music_tracks(state: MusicState, assets_dir: Path, console: ConsoleState) -> None:
    if not state.ready or not state.enabled:
        return

    music_dir = assets_dir / "music"
    if music_dir.exists() and music_dir.is_dir():
        loaded = 0
        for track_name, candidates in MUSIC_TRACKS.items():
            music = None
            for candidate in candidates:
                path = assets_dir / candidate
                if not path.exists():
                    continue
                music = rl.load_music_stream(str(path))
                if music is not None:
                    break
            if music is None:
                raise FileNotFoundError(f"audio: missing music file for track '{track_name}' in {music_dir}")
            rl.set_music_volume(music, state.volume)
            state.tracks[track_name] = music
            loaded += 1
        console.log.log(f"audio: music tracks loaded {loaded}/{len(MUSIC_TRACKS)} from files")
        console.log.flush()
        return

    paq_path = assets_dir / MUSIC_PAK_NAME
    if not paq_path.exists():
        raise FileNotFoundError(f"audio: missing {MUSIC_PAK_NAME} in {assets_dir}")

    entries: dict[str, bytes] = {}
    for name, data in paq.iter_entries(paq_path):
        entries[name.replace("\\", "/")] = data

    loaded = 0
    for track_name, candidates in MUSIC_TRACKS.items():
        data = None
        for candidate in candidates:
            data = entries.get(candidate)
            if data is not None:
                break
        if data is None:
            raise FileNotFoundError(f"audio: missing music entry for track '{track_name}' in {MUSIC_PAK_NAME}")
        music = rl.load_music_stream_from_memory(".ogg", data, len(data))
        rl.set_music_volume(music, state.volume)
        state.tracks[track_name] = music
        loaded += 1

    console.log.log(f"audio: music tracks loaded {loaded}/{len(MUSIC_TRACKS)}")
    console.log.flush()


def play_music(state: MusicState, track_name: str) -> None:
    if not state.ready or not state.enabled:
        return
    music = state.tracks.get(track_name)
    if music is None:
        return
    if state.active_track == track_name and rl.is_music_stream_playing(music):
        return
    rl.play_music_stream(music)
    state.active_track = track_name


def stop_music(state: MusicState) -> None:
    if not state.ready or not state.enabled:
        return
    if state.active_track is None:
        return
    music = state.tracks.get(state.active_track)
    if music is None:
        state.active_track = None
        return
    rl.stop_music_stream(music)
    state.active_track = None


def update_music(state: MusicState) -> None:
    if not state.ready or not state.enabled:
        return
    if state.active_track is None:
        return
    music = state.tracks.get(state.active_track)
    if music is None:
        return
    rl.update_music_stream(music)


def shutdown_music(state: MusicState) -> None:
    if not state.ready:
        return
    for music in state.tracks.values():
        try:
            rl.stop_music_stream(music)
            rl.unload_music_stream(music)
        except Exception:
            pass
    state.tracks.clear()
    state.active_track = None

