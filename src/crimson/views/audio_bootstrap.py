from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import random

from grim.audio import AudioState, init_audio_state
from grim.config import CrimsonConfig, ensure_crimson_cfg
from grim.console import ConsoleLog, ConsoleState

from ..assets_fetch import download_missing_paqs
from ..paths import default_runtime_dir


@dataclass(slots=True)
class ViewAudioBootstrap:
    config: CrimsonConfig | None
    console: ConsoleState | None
    audio: AudioState | None
    audio_rng: random.Random | None


def init_view_audio(assets_dir: Path, *, seed: int = 0xBEEF) -> ViewAudioBootstrap:
    runtime_dir = default_runtime_dir()
    runtime_dir.mkdir(parents=True, exist_ok=True)
    try:
        config = ensure_crimson_cfg(runtime_dir)
    except Exception:
        return ViewAudioBootstrap(None, None, None, None)

    console = ConsoleState(
        base_dir=runtime_dir,
        log=ConsoleLog(base_dir=runtime_dir),
        assets_dir=assets_dir,
    )
    try:
        download_missing_paqs(assets_dir, console)
    except Exception as exc:
        console.log.log(f"assets: download failed: {exc}")
        console.log.flush()

    try:
        audio = init_audio_state(config, assets_dir, console)
    except Exception:
        return ViewAudioBootstrap(config, console, None, None)

    return ViewAudioBootstrap(config, console, audio, random.Random(seed))
