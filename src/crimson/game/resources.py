from __future__ import annotations

from grim.assets import load_runtime_resources, unload_runtime_resources
from grim.audio import init_audio_state, shutdown_audio

from .types import GameState


class GameResources:
    """Application resources outlive every screen, including the intro."""

    def __init__(self, state: GameState) -> None:
        self.state = state

    def open(self) -> None:
        state = self.state
        if state.resources is None:
            state.resources = load_runtime_resources(state.assets_dir)
            state.console.log.log(f"runtime resources loaded: {len(state.resources.textures)} textures")
            state.console.log.flush()
        if state.audio is None:
            state.audio = init_audio_state(state.config, state.assets_dir, state.console)
            state.console.exec_line("exec music/game_tunes.txt")

    def close(self) -> None:
        if self.state.audio is not None:
            shutdown_audio(self.state.audio)
            self.state.audio = None
        unload_runtime_resources(self.state.resources)
        self.state.resources = None
