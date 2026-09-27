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
    session: DeterministicSession | None = None
    world_state: object | None = None
    player_count: int = 0
    ticks: LiveTickSource = field(default_factory=LiveTickSource)
    clock: FixedStepClock = field(default_factory=FixedStepClock)

    def reset(self) -> None:
        self.session = None
        self.world_state = None
        self.player_count = 0
        self.ticks = LiveTickSource()
        self.clock = FixedStepClock()

    def _ensure_session(self, runtime: WorldRuntime) -> DeterministicSession:
        world_state = runtime.world
        player_count = len(runtime.world.players)
        session = self.session
        if session is not None and self.world_state is world_state and int(self.player_count) == int(player_count):
            return session

        self.reset()
        session = DeterministicSession(
            world=world_state,
            game_mode=self.game_mode,
            detail_preset=runtime.detail_preset,
            violence_disabled=runtime.violence_disabled,
            game_tune_started=bool(runtime.game_tune_started),
            demo_mode_active=bool(runtime.demo_mode_active),
            perk_progression_enabled=False,
            apply_world_dt_steps=True,
        )
        self.session = session
        self.world_state = world_state
        self.player_count = int(player_count)
        return session

    def advance_frame(self, runtime: WorldRuntime, dt: float) -> int:
        """Run the ticks this frame's time covers; returns how many ran."""

        if not runtime.world.players:
            return 0
        session = self._ensure_session(runtime)
        session.demo_mode_active = bool(runtime.demo_mode_active)
        self.ticks.poll(self.frame_inputs(float(dt)))
        plans = []
        for _ in range(self.clock.advance(float(dt))):
            step = step_replay_tick(session, self.ticks.next_tick())
            runtime.advance_presentation_clock(dt_sim=step.dt_sim, game_tune_started=session.game_tune_started)
            plans.append(step.presentation)
        apply_presentation_plans(plans=plans, runtime=runtime)
        return len(plans)
