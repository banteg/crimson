from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pyray as rl

from .config import CrimsonConfig
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
class AudioState:
    ready: bool
    music_tracks: dict[str, rl.Music]
    active_track: str | None
    volume: float


def init_audio_state(
    config: CrimsonConfig, assets_dir: Path, console: ConsoleState
) -> AudioState:
    music_disabled = int(config.data.get("music_disable", 0)) != 0
    sound_disabled = int(config.data.get("sound_disable", 0)) != 0
    volume = float(config.data.get("music_volume", 1.0))
    if music_disabled or sound_disabled:
        console.log.log("audio: music disabled")
        console.log.flush()
        return AudioState(ready=False, music_tracks={}, active_track=None, volume=volume)
    if not rl.is_audio_device_ready():
        rl.init_audio_device()
    ready = bool(rl.is_audio_device_ready())
    if not ready:
        console.log.log("audio: device init failed")
        console.log.flush()
        return AudioState(ready=False, music_tracks={}, active_track=None, volume=volume)
    state = AudioState(ready=True, music_tracks={}, active_track=None, volume=volume)
    load_music_tracks(state, assets_dir, console)
    return state


def load_music_tracks(
    state: AudioState, assets_dir: Path, console: ConsoleState
) -> None:
    if not state.ready:
        return
    paq_path = assets_dir / MUSIC_PAK_NAME
    if not paq_path.exists():
        console.log.log(f"audio: missing {MUSIC_PAK_NAME}")
        console.log.flush()
        return
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
            continue
        try:
            music = rl.load_music_stream_from_memory(".ogg", data, len(data))
        except Exception:
            continue
        rl.set_music_volume(music, state.volume)
        state.music_tracks[track_name] = music
        loaded += 1
    console.log.log(f"audio: music tracks loaded {loaded}/{len(MUSIC_TRACKS)}")
    console.log.flush()


def play_music(state: AudioState, track_name: str) -> None:
    if not state.ready:
        return
    music = state.music_tracks.get(track_name)
    if music is None:
        return
    if state.active_track == track_name and rl.is_music_stream_playing(music):
        return
    rl.play_music_stream(music)
    state.active_track = track_name


def stop_music(state: AudioState) -> None:
    if not state.ready:
        return
    if state.active_track is None:
        return
    music = state.music_tracks.get(state.active_track)
    if music is None:
        state.active_track = None
        return
    rl.stop_music_stream(music)
    state.active_track = None


def update_audio(state: AudioState) -> None:
    if not state.ready:
        return
    if state.active_track is None:
        return
    music = state.music_tracks.get(state.active_track)
    if music is None:
        return
    rl.update_music_stream(music)


def shutdown_audio(state: AudioState) -> None:
    if state.ready:
        for music in state.music_tracks.values():
            try:
                rl.stop_music_stream(music)
                rl.unload_music_stream(music)
            except Exception:
                pass
        state.music_tracks.clear()
        rl.close_audio_device()
