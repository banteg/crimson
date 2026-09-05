from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Protocol

import msgspec

from .hooks import TickResult
from .presentation_step import DeterministicPresentationPlan
from .step_pipeline import DeterministicStepResult
from .world_state import WorldEvents


class SimMetadataSink(Protocol):
    def apply_step_metadata(
        self,
        *,
        events: WorldEvents,
        presentation: DeterministicPresentationPlan,
        dt_sim: float,
        game_tune_started: bool,
    ) -> None: ...


class PresentationTickOutput(msgspec.Struct, frozen=True):
    tick_index: int
    dt_sim: float
    presentation: DeterministicPresentationPlan | None


def apply_sim_metadata_tick_result(
    *,
    sim_world: SimMetadataSink,
    tick_result: TickResult,
    game_tune_started: bool,
) -> PresentationTickOutput:
    step = tick_result.payload

    apply_tick_to_sim(
        sim_world=sim_world,
        step=step,
        game_tune_started=bool(game_tune_started),
    )
    return PresentationTickOutput(
        tick_index=int(tick_result.source_tick.tick_index),
        dt_sim=float(step.dt_sim),
        presentation=step.presentation,
    )


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


def apply_sim_metadata_batch(
    *,
    sim_world: SimMetadataSink,
    completed_results: Sequence[TickResult],
    game_tune_started: bool,
) -> list[PresentationTickOutput]:
    return [
        apply_sim_metadata_tick_result(
            sim_world=sim_world,
            tick_result=tick_result,
            game_tune_started=bool(game_tune_started),
        )
        for tick_result in completed_results
    ]


def apply_presentation_outputs(
    *,
    outputs: Sequence[PresentationTickOutput],
    runtime: Any,
    apply_audio: bool,
    update_camera: bool = True,
) -> None:
    if not outputs:
        return

    runtime.sync_audio_bridge_state()
    for output in outputs:
        if output.presentation is not None:
            runtime.audio_bridge.apply_plan(plan=output.presentation, apply_audio=bool(apply_audio))
            if bool(update_camera):
                runtime.update_camera(float(output.dt_sim))
            terrain_fx = output.presentation.terrain_fx
            if not terrain_fx.is_empty():
                runtime.render_resources.consume_terrain_fx_batch(terrain_fx)
            runtime.audio_bridge.apply_post_plan(plan=output.presentation, apply_audio=apply_audio)
