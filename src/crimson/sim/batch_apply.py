from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol

from .hooks import TickResult
from .presentation_step import PresentationStepCommands
from .world_state import WorldEvents


class SimMetadataSink(Protocol):
    def apply_step_metadata(
        self,
        *,
        events: WorldEvents,
        presentation: PresentationStepCommands,
        command_hash: str,
        dt_sim: float,
        game_tune_started: bool,
    ) -> None: ...


class DeterministicStepPayload(Protocol):
    events: WorldEvents
    presentation: PresentationStepCommands | None
    command_hash: str
    dt_sim: float


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
    extract_step: Callable[[object], DeterministicStepPayload | None],
) -> PresentationTickOutput | None:
    payload = tick_result.payload
    if payload is None:
        return None
    step = extract_step(payload)
    if step is None:
        return None

    apply_tick_to_sim(
        sim_world=sim_world,
        step=step,
        game_tune_started=bool(game_tune_started),
    )
    return PresentationTickOutput(
        tick_index=int(tick_result.tick_index),
        dt_sim=float(step.dt_sim),
        presentation=step.presentation,
    )


def apply_tick_to_sim(
    *,
    sim_world: SimMetadataSink,
    step: DeterministicStepPayload,
    game_tune_started: bool,
) -> None:
    presentation = step.presentation if step.presentation is not None else PresentationStepCommands()
    sim_world.apply_step_metadata(
        events=step.events,
        presentation=presentation,
        command_hash=str(step.command_hash),
        dt_sim=float(step.dt_sim),
        game_tune_started=bool(game_tune_started),
    )


def apply_sim_metadata_batch(
    *,
    sim_world: SimMetadataSink,
    completed_results: Sequence[TickResult],
    game_tune_started: bool,
    extract_step: Callable[[object], DeterministicStepPayload | None],
) -> list[PresentationTickOutput]:
    outputs: list[PresentationTickOutput] = []
    for tick_result in completed_results:
        output = apply_sim_metadata_tick_result(
            sim_world=sim_world,
            tick_result=tick_result,
            game_tune_started=bool(game_tune_started),
            extract_step=extract_step,
        )
        if output is None:
            continue
        outputs.append(output)
    return outputs


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
