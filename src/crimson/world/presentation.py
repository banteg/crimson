from __future__ import annotations

from grim.audio import AudioState
from grim.rand import Crand

from ..audio_router import AudioRouter
from ..effects import FxQueue, FxQueueRotated
from ..sim.presentation_step import PresentationStepCommands
from .audio_bridge import AudioBridge
from .render_resources import RenderResources
from .terrain_runtime import TerrainRuntime


class PresentationLayer:
    """Render + audio + terrain composition layer.

    Composes RenderResources, AudioBridge, and TerrainRuntime into a single
    presentation owner.  The underlying components remain accessible for
    low-level use via public attributes.
    """

    def __init__(
        self,
        *,
        render_resources: RenderResources,
        audio_bridge: AudioBridge,
        terrain_runtime: TerrainRuntime,
    ) -> None:
        self.render_resources = render_resources
        self.audio_bridge = audio_bridge
        self.terrain_runtime = terrain_runtime

    # -- Render --

    @property
    def fx_queue(self) -> FxQueue:
        return self.render_resources.fx_queue

    @property
    def fx_queue_rotated(self) -> FxQueueRotated:
        return self.render_resources.fx_queue_rotated

    def bake_fx_queues(self) -> None:
        self.render_resources.bake_fx_queues()

    def open(self, *, terrain_seed: int) -> None:
        self.render_resources.open(terrain_seed=terrain_seed)

    def close(self) -> None:
        self.render_resources.close()

    # -- Audio --

    @property
    def router(self) -> AudioRouter:
        return self.audio_bridge.router

    def sync_audio(
        self,
        *,
        audio: AudioState | None,
        audio_rng: Crand,
        demo_mode_active: bool,
    ) -> None:
        self.audio_bridge.sync(
            audio=audio,
            audio_rng=audio_rng,
            demo_mode_active=demo_mode_active,
        )

    def apply_audio_plan(
        self,
        *,
        plan: PresentationStepCommands,
        apply_audio: bool = True,
    ) -> None:
        self.audio_bridge.apply_plan(plan=plan, apply_audio=apply_audio)

    # -- Terrain --

    def process_terrain_pending(self) -> None:
        self.terrain_runtime.process_pending()

    def schedule_terrain(self, *, seed: int, layers: int = 3) -> None:
        self.terrain_runtime.schedule_from_rng_seed(seed=seed, layers=layers)

    def apply_bootstrap_terrain(
        self,
        *,
        terrain_slots: tuple[int, int, int],
        seed: int,
        layers: int = 3,
    ) -> None:
        self.terrain_runtime.apply_bootstrap_terrain(
            terrain_slots=terrain_slots,
            seed=seed,
            layers=layers,
        )
