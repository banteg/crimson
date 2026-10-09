from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..game_modes import GameMode
from ..replay.ticks import LiveTickSource, step_replay_tick
from ..sim.batch_apply import apply_presentation_plans
from ..sim.clock import FixedStepClock
from ..sim.input import PlayerInput
from ..sim.sessions import DeterministicSession

if TYPE_CHECKING:
    from .runtime import WorldRuntime


@dataclass(slots=True)
class StandaloneTickHarness:
    """Runs a world outside BaseGameplayMode (attract demo, debug views) on the live tick path."""

    game_mode: GameMode
    # Called once per rendered frame with its delta.
    frame_inputs: Callable[[float], Sequence[PlayerInput]]
    ticks: LiveTickSource = field(default_factory=LiveTickSource)
    clock: FixedStepClock = field(default_factory=FixedStepClock)

    def reset(self) -> None:
        self.ticks = LiveTickSource()
        self.clock = FixedStepClock()

    def _ensure_session(self, runtime: WorldRuntime) -> DeterministicSession:
        """The runtime's session, or a fresh one over its world after a reset dropped it."""
        if runtime.session is None:
            self.reset()
            world = runtime.world
            world.state.game_mode = self.game_mode
            world.state.detail_preset = runtime.detail_preset
            world.state.violence_disabled = runtime.violence_disabled
            runtime.start_session(DeterministicSession.start(world=world, perk_progression_enabled=False))
        assert runtime.session is not None
        return runtime.session

    def advance_frame(self, runtime: WorldRuntime, dt: float) -> int:
        """Run the ticks this frame's time covers; returns how many ran."""

        session = self._ensure_session(runtime)
        self.ticks.poll(self.frame_inputs(float(dt)))
        plans = []
        for _ in range(self.clock.advance(float(dt))):
            step = step_replay_tick(session, self.ticks.next_tick())
            runtime.presentation.advance(step.dt_sim)
            plans.append(step.presentation)
        apply_presentation_plans(plans=plans, runtime=runtime)
        return len(plans)
