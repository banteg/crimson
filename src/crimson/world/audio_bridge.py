from __future__ import annotations

from collections.abc import Callable

from grim.audio import AudioState, play_music, play_sfx, trigger_game_tune
from grim.audio_math import native_sound_pan
from grim.geom import Vec2
from grim.rand import CrandLike
from grim.sfx import update_sfx
from grim.sfx_map import SfxId
from grim.sfx_types import SfxRequest

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

    def play_sfx(
        self,
        sfx: SfxId,
        *,
        reflex_boost_timer: float | None = None,
        gain: float = 1.0,
        pan: int = 0,
    ) -> None:
        if self.audio is None or not self.sfx_enabled:
            return
        if reflex_boost_timer is None:
            reflex_boost_timer = self._reflex_boost_timer()
        play_sfx(self.audio, sfx, reflex_boost_timer=reflex_boost_timer, gain=gain, pan=pan)

    def _play_request(
        self,
        request: SfxRequest,
        plan: DeterministicPresentationPlan,
        *,
        camera: Vec2,
        screen_width: float,
    ) -> None:
        self.play_sfx(
            request.sfx_id,
            reflex_boost_timer=plan.reflex_boost_timer,
            gain=request.gain * (0.7 if plan.demo_mode_active else 1.0),
            pan=native_sound_pan(request.position, camera=camera, screen_width=screen_width),
        )

    def apply_plan(
        self,
        *,
        plan: DeterministicPresentationPlan,
        apply_audio: bool = True,
        camera: Vec2 = Vec2(),
        screen_width: float = 1024.0,
    ) -> None:
        if not apply_audio:
            return
        if plan.trigger_game_tune and self.audio is not None:
            trigger_game_tune(self.audio, rng=self.audio_rng)
        for request in plan.sfx:
            self._play_request(request, plan, camera=camera, screen_width=screen_width)

    def apply_post_plan(
        self,
        *,
        plan: DeterministicPresentationPlan,
        apply_audio: bool = True,
        camera: Vec2 = Vec2(),
        screen_width: float = 1024.0,
    ) -> None:
        if not apply_audio:
            return
        for request in plan.post_apply_sfx:
            self._play_request(request, plan, camera=camera, screen_width=screen_width)
        if plan.play_quest_completion_music and self.audio is not None:
            play_music(self.audio, "crimsonquest", fade_in=True)
        if self.audio is not None:
            update_sfx(self.audio.sfx, plan.sfx_dt)
