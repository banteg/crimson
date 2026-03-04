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
        presentation: PresentationStepCommands | None,
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


def apply_tick_to_sim(
    *,
    sim_world: SimMetadataSink,
    step: DeterministicStepPayload,
    game_tune_started: bool,
) -> None:
    sim_world.apply_step_metadata(
        events=step.events,
        presentation=step.presentation,
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
        payload = tick_result.payload
        if payload is None:
            continue
        step = extract_step(payload)
        if step is None:
            continue

        apply_tick_to_sim(
            sim_world=sim_world,
            step=step,
            game_tune_started=bool(game_tune_started),
        )
        outputs.append(
            PresentationTickOutput(
                tick_index=int(tick_result.tick_index),
                dt_sim=float(step.dt_sim),
                presentation=step.presentation,
            ),
        )
    return outputs


def apply_presentation_outputs(
    *,
    outputs: Sequence[PresentationTickOutput],
    sync_audio_bridge_state: Callable[[], None],
    apply_audio_plan: Callable[[PresentationStepCommands, bool], None],
    update_camera: Callable[[float], None] | None,
    apply_audio: bool,
) -> None:
    if not outputs:
        return

    sync_audio_bridge_state()
    for output in outputs:
        if output.presentation is None:
            continue
        apply_audio_plan(output.presentation, bool(apply_audio))
    if update_camera is not None:
        update_camera(float(outputs[-1].dt_sim))
