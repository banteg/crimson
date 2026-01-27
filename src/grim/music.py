from __future__ import annotations

from dataclasses import dataclass, field
from collections.abc import Callable
from pathlib import Path
import random

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
    playbacks: dict[str, "TrackPlayback"] = field(default_factory=dict)
    queue: list[str] = field(default_factory=list)
    # Mirrors the original game's "start a random game tune on first hit" gate.
    game_tune_started: bool = False
    game_tune_track: str | None = None
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
        playbacks={},
        queue=[],
        game_tune_started=False,
        game_tune_track=None,
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


@dataclass(slots=True)
class TrackPlayback:
    """Runtime playback state for a loaded music stream."""

    music: rl.Music
    volume: float
    muted: bool


_MUSIC_MAX_DT = 0.1
_MUSIC_FADE_IN_PER_SEC = 1.0
_MUSIC_FADE_OUT_PER_SEC = 0.5


def play_music(state: MusicState, track_name: str) -> None:
    if not state.ready or not state.enabled:
        return
    music = state.tracks.get(track_name)
    if music is None:
        return

    # Original behavior uses an "exclusive" music channel: starting a new track
    # mutes (fades out) any currently-unmuted music.
    for key, pb in state.playbacks.items():
        if key != track_name:
            pb.muted = True

    pb = state.playbacks.get(track_name)
    if pb is None:
        pb = TrackPlayback(music=music, volume=0.0, muted=False)
        state.playbacks[track_name] = pb
    else:
        pb.muted = False

    playing = False
    try:
        playing = bool(rl.is_music_stream_playing(music))
    except Exception:
        playing = False

    # Mirror `sfx_play_exclusive`: if the track isn't already audible, start it
    # immediately at the target volume. Otherwise, let the fade logic bring it
    # back up (resume behavior).
    if (not playing) or pb.volume <= 0.0:
        pb.volume = state.volume
        try:
            rl.set_music_volume(music, pb.volume)
        except Exception:
            pass
        try:
            rl.play_music_stream(music)
        except Exception:
            pass

    state.active_track = track_name


def stop_music(state: MusicState) -> None:
    if not state.ready or not state.enabled:
        return
    # Mirror `sfx_mute_all`: mark everything muted and let `update_music` ramp it down.
    for pb in state.playbacks.values():
        pb.muted = True
    state.active_track = None
    state.game_tune_started = False
    state.game_tune_track = None


def trigger_game_tune(state: MusicState, *, rand: Callable[[], int] | None = None) -> str | None:
    """Start a random queued game tune, if it hasn't been triggered yet.

    Returns the track key if playback started, otherwise None.
    """
    if not state.ready or not state.enabled:
        return None
    if state.game_tune_started:
        return None
    if not state.queue:
        return None

    if rand is None:
        track_key = random.choice(state.queue)
    else:
        idx = int(rand()) % len(state.queue)
        track_key = state.queue[idx]

    if track_key not in state.tracks:
        return None

    play_music(state, track_key)
    state.game_tune_started = True
    state.game_tune_track = track_key
    return track_key


def update_music(state: MusicState, dt: float) -> None:
    if not state.ready or not state.enabled:
        return
    frame_dt = float(dt)
    if frame_dt <= 0.0:
        return
    if frame_dt > _MUSIC_MAX_DT:
        frame_dt = _MUSIC_MAX_DT

    target_volume = float(state.volume)
    if target_volume <= 0.0:
        # Original behavior: global music volume at 0 stops playback immediately.
        for track_key in list(state.playbacks.keys()):
            pb = state.playbacks.pop(track_key, None)
            if pb is None:
                continue
            try:
                rl.set_music_volume(pb.music, 0.0)
            except Exception:
                pass
            try:
                rl.stop_music_stream(pb.music)
            except Exception:
                pass
        return

    for track_key in list(state.playbacks.keys()):
        pb = state.playbacks.get(track_key)
        if pb is None:
            continue
        music = pb.music

        # Keep streams serviced while they play.
        try:
            if rl.is_music_stream_playing(music):
                rl.update_music_stream(music)
        except Exception:
            pass

        muted = pb.muted or target_volume <= 0.0
        if muted:
            pb.volume -= frame_dt * _MUSIC_FADE_OUT_PER_SEC
            if pb.volume <= 0.0:
                pb.volume = 0.0
                try:
                    rl.set_music_volume(music, 0.0)
                except Exception:
                    pass
                try:
                    rl.stop_music_stream(music)
                except Exception:
                    pass
                state.playbacks.pop(track_key, None)
                continue
            try:
                rl.set_music_volume(music, pb.volume)
            except Exception:
                pass
            continue

        # Unmuted track: ensure it stays playing and ramp toward target volume.
        try:
            if not rl.is_music_stream_playing(music):
                rl.play_music_stream(music)
        except Exception:
            pass

        if pb.volume > target_volume:
            pb.volume = target_volume
        elif pb.volume < target_volume:
            pb.volume = min(target_volume, pb.volume + frame_dt * _MUSIC_FADE_IN_PER_SEC)

        try:
            rl.set_music_volume(music, pb.volume)
        except Exception:
            pass


def set_music_volume(state: MusicState, volume: float) -> None:
    volume = float(volume)
    if volume < 0.0:
        volume = 0.0
    if volume > 1.0:
        volume = 1.0
    state.volume = volume
    if not state.ready or not state.enabled:
        return
    # Mirror original: volume decreases take effect immediately; increases are ramped
    # by `update_music`.
    for pb in state.playbacks.values():
        if pb.muted:
            continue
        if pb.volume > state.volume:
            pb.volume = state.volume
        try:
            rl.set_music_volume(pb.music, pb.volume)
        except Exception:
            pass


def shutdown_music(state: MusicState) -> None:
    if not state.ready:
        return
    for pb in list(state.playbacks.values()):
        try:
            rl.stop_music_stream(pb.music)
        except Exception:
            pass
    state.playbacks.clear()
    for music in state.tracks.values():
        try:
            rl.stop_music_stream(music)
            rl.unload_music_stream(music)
        except Exception:
            pass
    state.tracks.clear()
    state.active_track = None
    state.game_tune_started = False
    state.game_tune_track = None
