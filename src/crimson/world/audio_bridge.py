from __future__ import annotations

from collections.abc import Callable

from grim.audio import AudioState, play_music, play_sfx, trigger_game_tune
from grim.rand import CrandLike
from grim.sfx_map import SfxId

from ..sim.presentation_step import DeterministicPresentationPlan


class AudioBridge:
    def __init__(
        self,
        *,
        audio_rng: CrandLike,
        audio: AudioState | None = None,
        reflex_boost_timer: Callable[[], float] = lambda: 0.0,
    ) -> None:
        self.audio_rng = audio_rng
        self.audio = audio
        self.sfx_enabled = True
        self._reflex_boost_timer = reflex_boost_timer

    def sync(self, *, audio: AudioState | None, audio_rng: CrandLike) -> None:
        self.audio = audio
        self.audio_rng = audio_rng

    def play_sfx(self, sfx: SfxId, *, reflex_boost_timer: float | None = None) -> None:
        if self.audio is None or not self.sfx_enabled:
            return
        if reflex_boost_timer is None:
            reflex_boost_timer = self._reflex_boost_timer()
        play_sfx(self.audio, sfx, reflex_boost_timer=reflex_boost_timer)

    def apply_plan(self, *, plan: DeterministicPresentationPlan, apply_audio: bool = True) -> None:
        if not apply_audio:
            return
        if plan.trigger_game_tune and self.audio is not None:
            trigger_game_tune(self.audio, rng=self.audio_rng)
        for sfx in plan.sfx:
            self.play_sfx(sfx, reflex_boost_timer=plan.reflex_boost_timer)

    def apply_post_plan(self, *, plan: DeterministicPresentationPlan, apply_audio: bool = True) -> None:
        if not apply_audio:
            return
        for sfx in plan.post_apply_sfx:
            self.play_sfx(sfx, reflex_boost_timer=plan.reflex_boost_timer)
        if plan.play_quest_completion_music and self.audio is not None:
            play_music(self.audio, "crimsonquest", fade_in=True)
