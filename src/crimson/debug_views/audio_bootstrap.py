from __future__ import annotations

from pathlib import Path

import msgspec
from construct import ConstructError

from grim.audio import AudioState, init_audio_state
from grim.config import CrimsonConfig
from grim.console import ConsoleState
from grim.rand import Crand

from ..paths import default_runtime_dir
from ..runtime_boot import boot_runtime


class ViewAudioBootstrap(msgspec.Struct):
    config: CrimsonConfig | None
    console: ConsoleState | None
    audio: AudioState | None
    audio_rng: Crand


def init_view_audio(assets_dir: Path, *, seed: int = 0xBEEF) -> ViewAudioBootstrap:
    audio_rng = Crand(seed)
    try:
        boot = boot_runtime(default_runtime_dir(), assets_dir)
    except (ConstructError, OSError, ValueError):
        return ViewAudioBootstrap(None, None, None, audio_rng)

    try:
        audio = init_audio_state(boot.config, assets_dir, boot.console, audio_rng)
    except (ConstructError, OSError, RuntimeError, ValueError):
        return ViewAudioBootstrap(boot.config, boot.console, None, audio_rng)

    return ViewAudioBootstrap(boot.config, boot.console, audio, audio_rng)
