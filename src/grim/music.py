from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
from typing import cast

import msgspec

from grim.raylib_api import rl

from . import paq
from .console import ConsoleState
from .rand import CrandLike

MUSIC_PAK_NAME = "music.paq"
MUSIC_TRACKS: dict[str, tuple[str, ...]] = {
    "intro": ("music/intro.ogg", "intro.ogg"),
    "shortie_monk": ("music/shortie_monk.ogg", "shortie_monk.ogg"),
    "crimson_theme": ("music/crimson_theme.ogg", "crimson_theme.ogg"),
    "crimsonquest": ("music/crimsonquest.ogg", "crimsonquest.ogg"),
    "gt1_ingame": ("music/gt1_ingame.ogg", "gt1_ingame.ogg"),
    "gt2_harppen": ("music/gt2_harppen.ogg", "gt2_harppen.ogg"),
}


class MusicTrack(msgspec.Struct):
    """One owned stream and its native exclusive-playback state."""

    stream: rl.Music
    track_id: int
    source_data: bytes | None = None
    volume: float = 0.0
    muted: bool = True
    paused: bool = False

    def close(self) -> None:
        # Memory-backed Vorbis streams borrow source_data until decoder teardown.
        rl.unload_music_stream(self.stream)
        self.source_data = None


class MusicState(msgspec.Struct):
    ready: bool
    enabled: bool
    volume: float
    tracks: dict[str, MusicTrack] = msgspec.field(default_factory=dict)
    active_track: str | None = None
    queue: list[str] = msgspec.field(default_factory=list)
    # Mirrors the original game's "start a random game tune on first hit" gate.
    game_tune_started: bool = False
    paq_entries: dict[str, bytes] | None = None

    @property
    def next_track_id(self) -> int:
        return len(self.tracks)


def init_music_state(*, ready: bool, enabled: bool, volume: float) -> MusicState:
    return MusicState(ready=ready, enabled=enabled, volume=float(volume))


def load_music_tracks(state: MusicState, assets_dir: Path, console: ConsoleState) -> None:
    if not state.ready or not state.enabled:
        return

    paq_path = assets_dir / MUSIC_PAK_NAME
    if not paq_path.exists():
        raise FileNotFoundError(f"audio: missing {MUSIC_PAK_NAME} in {assets_dir}")

    entries: dict[str, bytes] = {}
    for name, data in paq.iter_entries(paq_path):
        entries[name.replace("\\", "/")] = data

    payloads: dict[str, bytes] = {}
    for track_name, candidates in MUSIC_TRACKS.items():
        data = None
        for candidate in candidates:
            data = entries.get(candidate)
            if data is not None:
                break
        if data is None:
            raise FileNotFoundError(f"audio: missing music entry for track '{track_name}' in {MUSIC_PAK_NAME}")
        payloads[track_name] = data

    with ExitStack() as cleanup:
        tracks: dict[str, MusicTrack] = {}
        for track_name, data in payloads.items():
            if track_name in state.tracks:
                continue
            stream = rl.load_music_stream_from_memory(".ogg", cast(str, data), len(data))
            track = MusicTrack(stream=stream, track_id=state.next_track_id + len(tracks), source_data=data)
            cleanup.callback(track.close)
            if not rl.is_music_valid(stream):
                raise ValueError(f"audio: failed to decode music track '{track_name}' in {MUSIC_PAK_NAME}")
            rl.set_music_volume(stream, state.volume)
            tracks[track_name] = track
        state.tracks.update(tracks)
        cleanup.pop_all()
    state.paq_entries = entries

    console.log.log(f"audio: music tracks loaded {len(payloads)}/{len(MUSIC_TRACKS)} from {paq_path}")
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
    if not state.ready or not state.enabled:
        if console is not None:
            console.log.log(f"SFX Tune {state.next_track_id} <- '{normalized}' FAILED")
        return None
    key = _normalize_track_key(normalized)
    track = state.tracks.get(key)
    if track is not None:
        if console is not None:
            console.log.log(f"SFX Tune {track.track_id} <- '{normalized}' ok")
        return key, track.track_id
    data = None
    music_stream = None
    file_path = assets_dir / normalized
    if file_path.is_file():
        music_stream = rl.load_music_stream(str(file_path))
    if music_stream is None:
        entries = _ensure_music_entries(state, assets_dir)
        if entries is not None:
            data = entries.get(normalized)
            if data is None:
                data = entries.get(Path(normalized).name)
            if data is not None:
                music_stream = rl.load_music_stream_from_memory(".ogg", cast(str, data), len(data))
    if music_stream is None or not rl.is_music_valid(music_stream):
        if music_stream is not None:
            rl.unload_music_stream(music_stream)
        if console is not None:
            console.log.log(f"SFX Tune {state.next_track_id} <- '{normalized}' FAILED")
        return None
    track_id = state.next_track_id
    track = MusicTrack(stream=music_stream, track_id=track_id, source_data=data)
    with ExitStack() as cleanup:
        cleanup.callback(track.close)
        rl.set_music_volume(music_stream, state.volume)
        state.tracks[key] = track
        cleanup.pop_all()
    if console is not None:
        console.log.log(f"SFX Tune {track_id} <- '{normalized}' ok")
    return key, int(track_id)


def queue_track(state: MusicState, track_key: str) -> None:
    if not state.ready or not state.enabled:
        return
    state.queue.append(track_key)


_MUSIC_MAX_DT = 0.1
_MUSIC_FADE_IN_PER_SEC = 1.0
_MUSIC_FADE_OUT_PER_SEC = 0.5


def play_music(state: MusicState, track_name: str, *, fade_in: bool = False) -> None:
    if not state.ready or not state.enabled:
        return
    track = state.tracks.get(track_name)
    if track is None:
        return

    state.game_tune_started = False
    for key, other in state.tracks.items():
        if key != track_name:
            other.muted = True

    # Native sfx_play_exclusive only unmutes a requested track at silence.
    # Callers that request a fading track keep retrying until it reaches zero.
    if track.volume <= 0.0:
        rl.stop_music_stream(track.stream)
        rl.set_music_volume(track.stream, 0.0 if fade_in else state.volume)
        rl.play_music_stream(track.stream)
        track.paused = False
        track.muted = False
        track.volume = state.volume
    if fade_in:
        track.volume = 0.0
        rl.set_music_volume(track.stream, 0.0)
    state.active_track = track_name


def stop_music(state: MusicState) -> None:
    if not state.ready or not state.enabled:
        return
    for track in state.tracks.values():
        track.muted = True
    state.active_track = None
    state.game_tune_started = False


def trigger_game_tune(state: MusicState, *, rng: CrandLike) -> str | None:
    """Select a queued tune once per run, retaining intent even at zero volume."""
    if not state.ready or not state.enabled or state.game_tune_started or not state.queue:
        return None
    track_key = state.queue[rng.rand() % len(state.queue)]
    play_music(state, track_key)
    state.game_tune_started = True
    return track_key


def update_music(state: MusicState, dt: float) -> None:
    if not state.ready or not state.enabled or dt <= 0.0:
        return
    frame_dt = min(float(dt), _MUSIC_MAX_DT)
    target_volume = state.volume
    for track in state.tracks.values():
        stream = track.stream
        playing = rl.is_music_stream_playing(stream)
        if playing:
            rl.update_music_stream(stream)
        if target_volume <= 0.0:
            # Native stops the buffer without seeking or forgetting its unmuted
            # state. Raylib Pause/Resume preserves the stream cursor likewise.
            if playing:
                rl.pause_music_stream(stream)
                track.paused = True
        elif not track.muted and not playing:
            if track.paused:
                rl.resume_music_stream(stream)
            else:
                rl.play_music_stream(stream)
            track.paused = False

        if track.muted:
            if track.volume > 0.0:
                track.volume = max(0.0, track.volume - frame_dt * _MUSIC_FADE_OUT_PER_SEC)
                if track.volume == 0.0:
                    rl.stop_music_stream(stream)
                    track.paused = False
                rl.set_music_volume(stream, track.volume)
        else:
            if track.volume > target_volume:
                track.volume = target_volume
            elif track.volume < target_volume:
                track.volume = min(target_volume, track.volume + frame_dt * _MUSIC_FADE_IN_PER_SEC)
            rl.set_music_volume(stream, track.volume)


def set_music_volume(state: MusicState, volume: float) -> None:
    state.volume = min(1.0, max(0.0, float(volume)))
    if not state.ready or not state.enabled:
        return
    for track in state.tracks.values():
        if not track.muted:
            track.volume = min(track.volume, state.volume)
            rl.set_music_volume(track.stream, track.volume)


def shutdown_music(state: MusicState) -> None:
    with ExitStack() as cleanup:
        for track in state.tracks.values():
            cleanup.callback(track.close)
        state.tracks.clear()
        state.queue.clear()
        state.paq_entries = None
        state.active_track = None
        state.game_tune_started = False
        state.ready = False
