from __future__ import annotations

from collections.abc import Callable
from typing import cast

import msgspec

from grim.audio import AudioState
from grim.rand import Crand

from ..audio_router import AudioRouter
from ..sim.presentation_step import PresentationStepCommands, apply_presentation_plan


def _zero_reflex_boost() -> float:
    return 0.0


class AudioBridge(msgspec.Struct):
    demo_mode_active: bool = False
    reflex_boost_timer_source: Callable[[], float] = _zero_reflex_boost
    audio: AudioState | None = None
    audio_rng: Crand | None = None
    router: AudioRouter = cast(AudioRouter, None)

    def __post_init__(self) -> None:
        self.router = AudioRouter(
            audio=self.audio,
            audio_rng=self.audio_rng,
            demo_mode_active=bool(self.demo_mode_active),
            reflex_boost_timer_source=self.reflex_boost_timer_source,
        )

    def sync(
        self,
        *,
        audio: AudioState | None,
        audio_rng: Crand | None,
        demo_mode_active: bool,
    ) -> None:
        AudioRouter._validate_audio_binding(audio, audio_rng)
        self.audio = audio
        self.audio_rng = audio_rng
        self.demo_mode_active = bool(demo_mode_active)
        self.router.audio = audio
        self.router.audio_rng = audio_rng
        self.router.demo_mode_active = bool(demo_mode_active)

    def apply_plan(self, *, plan: PresentationStepCommands, apply_audio: bool = True) -> None:
        apply_presentation_plan(
            plan=plan,
            audio_sink=self.router,
            apply_audio=bool(apply_audio),
        )
