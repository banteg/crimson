from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Protocol

from .presentation_step import DeterministicPresentationPlan
from .step_pipeline import DeterministicStepResult
from .world_state import WorldEvents

if TYPE_CHECKING:
    from ..world.runtime import WorldRuntime


class SimMetadataSink(Protocol):
    def apply_step_metadata(
        self,
        *,
        events: WorldEvents,
        presentation: DeterministicPresentationPlan,
        dt_sim: float,
        game_tune_started: bool,
    ) -> None: ...


def apply_tick_to_sim(
    *,
    sim_world: SimMetadataSink,
    step: DeterministicStepResult,
    game_tune_started: bool,
) -> None:
    sim_world.apply_step_metadata(
        events=step.events,
        presentation=step.presentation,
        dt_sim=float(step.dt_sim),
        game_tune_started=bool(game_tune_started),
    )


def apply_presentation_plans(
    *,
    plans: Sequence[DeterministicPresentationPlan],
    runtime: WorldRuntime,
    apply_audio: bool,
    update_camera: bool = True,
) -> None:
    if not plans:
        return

    runtime.sync_audio_bridge_state()
    for plan in plans:
        # Capture the viewport before this tick's post-step camera update.
        # Camera updates carry tick-local focus/shake, so batched application
        # never reads positions from a later simulation world.
        view = runtime.view_transform()
        runtime.audio_bridge.apply_plan(
            plan=plan,
            apply_audio=bool(apply_audio),
            camera=view.camera,
            screen_width=view.screen_size.x,
        )
        if update_camera and plan.camera is not None:
            runtime.update_camera(plan.camera)
        if not plan.terrain_fx.is_empty():
            runtime.render_resources.consume_terrain_fx_batch(plan.terrain_fx)
        runtime.audio_bridge.apply_post_plan(
            plan=plan,
            apply_audio=apply_audio,
            camera=view.camera,
            screen_width=view.screen_size.x,
        )
