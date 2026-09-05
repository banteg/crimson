from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path

import msgspec

from grim.raylib_api import rl

from . import music, sfx
from .config import CrimsonConfig
from .console import ConsoleState
from .rand import CrandLike
from .sfx_map import SfxId


class AudioState(msgspec.Struct):
    ready: bool
    music: music.MusicState
    sfx: sfx.SfxState
    owns_device: bool = False


def init_audio_state(config: CrimsonConfig, assets_dir: Path, console: ConsoleState) -> AudioState:
    music_disabled = config.audio.music_disabled
    sound_disabled = config.audio.sound_disabled
    music_volume = config.audio.music_volume
    sfx_volume = config.audio.sfx_volume

    music_enabled = not music_disabled
    sfx_enabled = not sound_disabled
    if not music_enabled and not sfx_enabled:
        console.log.log("audio: disabled (music + sfx)")
        console.log.flush()
        return AudioState(
            ready=False,
            music=music.init_music_state(ready=False, enabled=False, volume=music_volume),
            sfx=sfx.init_sfx_state(ready=False, enabled=False, volume=sfx_volume),
        )

    owns_device = not rl.is_audio_device_ready()
    if owns_device:
        rl.init_audio_device()
    ready = rl.is_audio_device_ready()
    if not ready:
        console.log.log("audio: device init failed")
        console.log.flush()
        return AudioState(
            ready=False,
            music=music.init_music_state(ready=False, enabled=False, volume=music_volume),
            sfx=sfx.init_sfx_state(ready=False, enabled=False, volume=sfx_volume),
        )

    state = AudioState(
        ready=True,
        music=music.init_music_state(ready=True, enabled=music_enabled, volume=music_volume),
        sfx=sfx.init_sfx_state(ready=True, enabled=sfx_enabled, volume=sfx_volume),
        owns_device=owns_device,
    )
    with ExitStack() as cleanup:
        cleanup.callback(shutdown_audio, state)
        sfx.load_sfx_index(state.sfx, assets_dir, console)
        music.load_music_tracks(state.music, assets_dir, console)
        cleanup.pop_all()
    return state


def play_music(state: AudioState, track_name: str, *, fade_in: bool = False) -> None:
    music.play_music(state.music, track_name, fade_in=fade_in)


def stop_music(state: AudioState | None) -> None:
    if state is None:
        return
    music.stop_music(state.music)


def trigger_game_tune(state: AudioState, *, rng: CrandLike) -> str | None:
    return music.trigger_game_tune(state.music, rng=rng)


def play_sfx(
    state: AudioState | None,
    sfx_id: SfxId,
    *,
    reflex_boost_timer: float = 0.0,
) -> None:
    if state is None:
        return
    sfx.play_sfx(state.sfx, sfx_id, reflex_boost_timer=float(reflex_boost_timer))


def set_sfx_volume(state: AudioState | None, volume: float) -> None:
    if state is None:
        return
    sfx.set_sfx_volume(state.sfx, volume)


def set_music_volume(state: AudioState | None, volume: float) -> None:
    if state is None:
        return
    music.set_music_volume(state.music, volume)


def update_audio(state: AudioState, dt: float) -> None:
    music.update_music(state.music, dt)


def shutdown_audio(state: AudioState) -> None:
    with ExitStack() as cleanup:
        if state.owns_device:
            cleanup.callback(rl.close_audio_device)
            state.owns_device = False
        cleanup.callback(music.shutdown_music, state.music)
        cleanup.callback(sfx.shutdown_sfx, state.sfx)
        state.ready = False
