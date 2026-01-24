from __future__ import annotations

from dataclasses import dataclass, field
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
    queue: list[str] = field(default_factory=list)
    track_ids: dict[str, int] = field(default_factory=dict)
    next_track_id: int = 0
    paq_entries: dict[str, bytes] | None = None


def init_music_state(*, ready: bool, enabled: bool, volume: float) -> MusicState:
    return MusicState(
        ready=ready,
        enabled=enabled,
        volume=float(volume),
        tracks={},
        active_track=None,
        queue=[],
        track_ids={},
        next_track_id=0,
        paq_entries=None,
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
        state.track_ids = {name: idx for idx, name in enumerate(state.tracks.keys())}
        state.next_track_id = len(state.track_ids)
        state.paq_entries = None
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
    state.track_ids = {name: idx for idx, name in enumerate(state.tracks.keys())}
    state.next_track_id = len(state.track_ids)
    state.paq_entries = entries

    console.log.log(f"audio: music tracks loaded {loaded}/{len(MUSIC_TRACKS)}")
    console.log.flush()


def _normalize_track_key(rel_path: str) -> str:
    name = Path(rel_path.replace("\\", "/")).name
    if name.lower().endswith(".ogg"):
        return name[:-4]
    return name


def _ensure_music_entries(state: MusicState, assets_dir: Path) -> dict[str, bytes] | None:
    if state.paq_entries is not None:
        return state.paq_entries
    paq_path = assets_dir / MUSIC_PAK_NAME
    if not paq_path.exists():
        return None
    entries: dict[str, bytes] = {}
    for name, data in paq.iter_entries(paq_path):
        entries[name.replace("\\", "/")] = data
    state.paq_entries = entries
    return entries


def load_music_track(
    state: MusicState,
    assets_dir: Path,
    rel_path: str,
    *,
    console: ConsoleState | None = None,
) -> tuple[str, int] | None:
    normalized = rel_path.replace("\\", "/")
    track_id = state.next_track_id
    state.next_track_id += 1
    if not state.ready or not state.enabled:
        if console is not None:
            console.log.log(f"SFX Tune {track_id} <- '{normalized}' FAILED")
        return None
    key = _normalize_track_key(normalized)
    existing = state.tracks.get(key)
    if existing is not None:
        existing_id = state.track_ids.get(key)
        if existing_id is None:
            state.track_ids[key] = track_id
            existing_id = track_id
        if console is not None:
            console.log.log(f"SFX Tune {existing_id} <- '{normalized}' ok")
        return key, int(existing_id)
    music_stream = None
    file_path = assets_dir / normalized
    if file_path.is_file():
        music_stream = rl.load_music_stream(str(file_path))
    else:
        entries = _ensure_music_entries(state, assets_dir)
        if entries is not None:
            data = entries.get(normalized)
            if data is None:
                data = entries.get(Path(normalized).name)
            if data is not None:
                music_stream = rl.load_music_stream_from_memory(".ogg", data, len(data))
    if music_stream is None:
        if console is not None:
            console.log.log(f"SFX Tune {track_id} <- '{normalized}' FAILED")
        return None
    rl.set_music_volume(music_stream, state.volume)
    state.tracks[key] = music_stream
    state.track_ids[key] = track_id
    if console is not None:
        console.log.log(f"SFX Tune {track_id} <- '{normalized}' ok")
    return key, track_id


def queue_track(state: MusicState, track_key: str) -> None:
    if not state.ready or not state.enabled:
        return
    state.queue.append(track_key)


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


def set_music_volume(state: MusicState, volume: float) -> None:
    volume = float(volume)
    if volume < 0.0:
        volume = 0.0
    if volume > 1.0:
        volume = 1.0
    state.volume = volume
    if not state.ready or not state.enabled:
        return
    for music in state.tracks.values():
        try:
            rl.set_music_volume(music, state.volume)
        except Exception:
            pass


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
