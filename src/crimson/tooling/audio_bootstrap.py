from __future__ import annotations

from pathlib import Path

import msgspec
from construct import ConstructError

from grim.audio import AudioState, init_audio_state
from grim.config import CrimsonConfig, ensure_crimson_cfg
from grim.console import ConsoleLog, ConsoleState
from grim.rand import Crand

from ..assets_fetch import download_missing_paqs
from ..paths import default_runtime_dir


class ViewAudioBootstrap(msgspec.Struct):
    config: CrimsonConfig | None
    console: ConsoleState | None
    audio: AudioState | None
    audio_rng: Crand


def init_view_audio(assets_dir: Path, *, seed: int = 0xBEEF) -> ViewAudioBootstrap:
    audio_rng = Crand(seed)
    runtime_dir = default_runtime_dir()
    runtime_dir.mkdir(parents=True, exist_ok=True)
    try:
        config = ensure_crimson_cfg(runtime_dir)
    except (ConstructError, OSError, ValueError):
        return ViewAudioBootstrap(None, None, None, audio_rng)

    console = ConsoleState(
        base_dir=runtime_dir,
        log=ConsoleLog(base_dir=runtime_dir),
        assets_dir=assets_dir,
    )
    try:
        download_missing_paqs(assets_dir, console)
    except (OSError, ValueError) as exc:
        console.log.log(f"assets: download failed: {exc}")
        console.log.flush()

    try:
        audio = init_audio_state(config, assets_dir, console)
    except (ConstructError, OSError, RuntimeError, ValueError):
        return ViewAudioBootstrap(config, console, None, audio_rng)

    return ViewAudioBootstrap(config, console, audio, audio_rng)
