from __future__ import annotations

from grim.audio import AudioState, play_music
from grim.rand import CrandLike
from grim.raylib_api import rl
from grim.sfx_map import SfxId

from ..audio_router import AudioRouter, AudioRouterRuntime
from ..sim.presentation_step import DeterministicPresentationPlan, PresentationPlanRuntime, apply_presentation_plan


class AudioBridge:
    def __init__(
        self,
        *,
        audio_rng: CrandLike,
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
        audio_rng: CrandLike,
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

    def apply_post_plan(self, *, plan: DeterministicPresentationPlan, apply_audio: bool = True) -> None:
        if not apply_audio:
            return
        for sfx in plan.post_apply_sfx:
            self.router.play_sfx(sfx)
        if plan.play_quest_completion_music and self.audio is not None:
            play_music(self.audio, "crimsonquest")
            playback = self.audio.music.playbacks.get("crimsonquest")
            if playback is not None:
                playback.volume = 0.0
                try:
                    rl.set_music_volume(playback.music, 0.0)
                except RuntimeError:
                    playback.volume = 0.0


class _AudioBridgePresentationPlanRuntime(PresentationPlanRuntime):
    bridge: AudioBridge

    def trigger_game_tune(self) -> str | None:
        return self.bridge.router.trigger_game_tune()

    def play_sfx(self, sfx: SfxId) -> None:
        self.bridge.router.play_sfx(sfx)
