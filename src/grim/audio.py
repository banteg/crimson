from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import random

import pyray as rl

from .config import CrimsonConfig
from .console import ConsoleState
from . import music, sfx


@dataclass(slots=True)
class AudioState:
    ready: bool
    music: music.MusicState
    sfx: sfx.SfxState


def init_audio_state(config: CrimsonConfig, assets_dir: Path, console: ConsoleState) -> AudioState:
    music_disabled = int(config.data.get("music_disable", 0)) != 0
    sound_disabled = int(config.data.get("sound_disable", 0)) != 0
    music_volume = float(config.data.get("music_volume", 1.0))
    sfx_volume = float(config.data.get("sfx_volume", 1.0))

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

    if not rl.is_audio_device_ready():
        rl.init_audio_device()
    ready = bool(rl.is_audio_device_ready())
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
    )
    sfx.load_sfx_index(state.sfx, assets_dir, console)
    music.load_music_tracks(state.music, assets_dir, console)
    return state


def play_music(state: AudioState, track_name: str) -> None:
    music.play_music(state.music, track_name)


def stop_music(state: AudioState) -> None:
    music.stop_music(state.music)


def trigger_game_tune(state: AudioState, *, rng: random.Random | None = None) -> str | None:
    return music.trigger_game_tune(state.music, rng=rng)


def play_sfx(
    state: AudioState | None,
    key: str | None,
    *,
    rng: random.Random | None = None,
    allow_variants: bool = True,
) -> None:
    if state is None:
        return
    sfx.play_sfx(state.sfx, key, rng=rng, allow_variants=allow_variants)


def set_sfx_volume(state: AudioState | None, volume: float) -> None:
    if state is None:
        return
    sfx.set_sfx_volume(state.sfx, volume)


def set_music_volume(state: AudioState | None, volume: float) -> None:
    if state is None:
        return
    music.set_music_volume(state.music, volume)


def update_audio(state: AudioState) -> None:
    music.update_music(state.music)


def shutdown_audio(state: AudioState) -> None:
    if not state.ready:
        return
    sfx.shutdown_sfx(state.sfx)
    music.shutdown_music(state.music)
    rl.close_audio_device()
