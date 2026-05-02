from __future__ import annotations

from grim.audio import AudioState
from grim.rand import Crand
from grim.sfx_map import SfxId

from ..audio_router import AudioRouter, AudioRouterRuntime
from ..sim.presentation_step import DeterministicPresentationPlan, PresentationPlanRuntime, apply_presentation_plan


class AudioBridge:
    def __init__(
        self,
        *,
        audio_rng: Crand,
        demo_mode_active: bool = False,
        runtime: AudioRouterRuntime | None = None,
        audio: AudioState | None = None,
    ) -> None:
        self.audio_rng = audio_rng
        self.demo_mode_active = bool(demo_mode_active)
        self.audio = audio
        self.runtime = runtime if runtime is not None else AudioRouterRuntime()
        self.router = AudioRouter(
            audio_rng=self.audio_rng,
            audio=self.audio,
            demo_mode_active=bool(self.demo_mode_active),
            runtime=self.runtime,
        )

    def sync(
        self,
        *,
        audio: AudioState | None,
        audio_rng: Crand,
        demo_mode_active: bool,
    ) -> None:
        self.audio = audio
        self.audio_rng = audio_rng
        self.demo_mode_active = bool(demo_mode_active)
        self.router.audio = audio
        self.router.audio_rng = audio_rng
        self.router.demo_mode_active = bool(demo_mode_active)

    def apply_plan(self, *, plan: DeterministicPresentationPlan, apply_audio: bool = True) -> None:
        apply_presentation_plan(
            plan=plan,
            runtime=_AudioBridgePresentationPlanRuntime(bridge=self),
            apply_audio=bool(apply_audio),
        )


class _AudioBridgePresentationPlanRuntime(PresentationPlanRuntime):
    bridge: AudioBridge

    def trigger_game_tune(self) -> str | None:
        return self.bridge.router.trigger_game_tune()

    def play_sfx(self, sfx: SfxId) -> None:
        self.bridge.router.play_sfx(sfx)
