from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol

from .hooks import TickResult
from .presentation_step import PresentationStepCommands
from .step_pipeline import DeterministicStepResult
from .world_state import WorldEvents


class SimMetadataSink(Protocol):
    def apply_step_metadata(
        self,
        *,
        events: WorldEvents,
        presentation: PresentationStepCommands,
        dt_sim: float,
        game_tune_started: bool,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class PresentationTickOutput:
    tick_index: int
    dt_sim: float
    presentation: PresentationStepCommands | None


def apply_sim_metadata_tick_result(
    *,
    sim_world: SimMetadataSink,
    tick_result: TickResult,
    game_tune_started: bool,
) -> PresentationTickOutput:
    step = tick_result.payload.step

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
    sync_audio_bridge_state: Callable[[], None],
    apply_audio_plan: Callable[[PresentationStepCommands, bool], None],
    update_camera: Callable[[float], None] | None,
    on_output_applied: Callable[[PresentationTickOutput], None] | None = None,
    apply_audio: bool,
) -> None:
    if not outputs:
        return

    sync_audio_bridge_state()
    for output in outputs:
        if output.presentation is None:
            if on_output_applied is not None:
                on_output_applied(output)
            continue
        apply_audio_plan(output.presentation, bool(apply_audio))
        if update_camera is not None:
            update_camera(float(output.dt_sim))
        if on_output_applied is not None:
            on_output_applied(output)
