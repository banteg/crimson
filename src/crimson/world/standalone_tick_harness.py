from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..game_modes import GameMode
from ..sim.batch_apply import (
    PresentationApplyRuntime,
    PresentationTickOutput,
    apply_presentation_outputs,
    apply_sim_metadata_batch,
)
from ..sim.clock import FixedStepClock
from ..sim.frame_pump import advance_tick_runner_frame
from ..sim.input_providers import LocalInputProvider, LocalInputRuntime
from ..sim.presentation_reactions import (
    PostApplyReaction,
    apply_post_apply_reaction,
    build_post_apply_reaction,
)
from ..sim.sessions import DeterministicSession
from ..sim.tick_runner import TickBatchResult, TickRunner, TickRunnerConfig

if TYPE_CHECKING:
    from .runtime import WorldRuntime


class _StandalonePresentationApplyRuntime(PresentationApplyRuntime):
    runtime: WorldRuntime
    reactions_by_tick: dict[int, PostApplyReaction]

    def output_applied(self, output: PresentationTickOutput) -> None:
        apply_post_apply_reaction(
            reaction=self.reactions_by_tick.get(int(output.tick_index), PostApplyReaction()),
            play_sfx=self.runtime.audio_bridge.router.play_sfx,
        )


@dataclass(slots=True)
class StandaloneTickHarness:
    """Standalone local runner for demo/debug screens outside BaseGameplayMode."""

    game_mode: GameMode
    input_runtime: LocalInputRuntime
    tick_rate: int = 60
    session: DeterministicSession | None = None
    runner: TickRunner | None = None
    world_state: object | None = None
    player_count: int = 0
    clock: FixedStepClock = field(init=False)
    frame_index: int = 0
    next_tick_index: int = 0

    def __post_init__(self) -> None:
        self.tick_rate = max(1, int(self.tick_rate))
        self.clock = FixedStepClock(tick_rate=int(self.tick_rate))

    def reset(self) -> None:
        self.session = None
        self.runner = None
        self.world_state = None
        self.player_count = 0
        self.clock = FixedStepClock(tick_rate=int(self.tick_rate))
        self.frame_index = 0
        self.next_tick_index = 0

    def _ensure_runner(self, runtime: WorldRuntime) -> tuple[TickRunner, DeterministicSession]:
        world_state = runtime.sim_world.world_state
        player_count = len(runtime.sim_world.players)
        session = self.session
        runner = self.runner
        if (
            session is not None
            and runner is not None
            and self.world_state is world_state
            and int(self.player_count) == int(player_count)
        ):
            return runner, session

        detail_preset = 5
        violence_disabled = 0
        config = runtime.config
        if config is not None:
            detail_preset = config.display.detail_preset
            violence_disabled = config.display.violence_disabled

        session = DeterministicSession(
            world=world_state,
            world_size=float(runtime.world_size),
            damage_scale_by_type=runtime.sim_world.damage_scale_by_type,
            game_mode=self.game_mode,
            detail_preset=int(detail_preset),
            violence_disabled=int(violence_disabled),
            game_tune_started=bool(runtime.sim_world.game_tune_started),
            demo_mode_active=bool(runtime.demo_mode_active),
            perk_progression_enabled=False,
            apply_world_dt_steps=True,
        )
        provider = LocalInputProvider(
            player_count=int(player_count),
            runtime=self.input_runtime,
        )
        runner = TickRunner(
            session=session,
            input_provider=provider,
            config=TickRunnerConfig(),
        )
        self.session = session
        self.runner = runner
        self.world_state = world_state
        self.player_count = int(player_count)
        self.clock = FixedStepClock(tick_rate=int(self.tick_rate))
        self.frame_index = 0
        self.next_tick_index = 0
        return runner, session

    def _apply_tick_batch(
        self,
        runtime: WorldRuntime,
        *,
        batch: TickBatchResult,
        session: DeterministicSession,
    ) -> int:
        outputs = apply_sim_metadata_batch(
            sim_world=runtime.sim_world,
            completed_results=batch.completed_results,
            game_tune_started=bool(session.game_tune_started),
        )
        reactions = {
            int(result.source_tick.tick_index): build_post_apply_reaction(tick_result=result)
            for result in batch.completed_results
        }
        apply_presentation_outputs(
            outputs=outputs,
            runtime=runtime,
            apply_runtime=_StandalonePresentationApplyRuntime(
                runtime=runtime,
                reactions_by_tick=reactions,
            ),
            apply_audio=True,
        )
        return len(outputs)

    def advance_frame(self, runtime: WorldRuntime, dt: float) -> int:
        if not runtime.sim_world.players:
            return 0
        runtime.terrain_runtime.process_pending()
        runner, session = self._ensure_runner(runtime)
        session.demo_mode_active = bool(runtime.demo_mode_active)
        dt = float(dt)
        ticks_requested = int(self.clock.advance(dt))
        advance = advance_tick_runner_frame(
            runner=runner,
            start_tick=int(self.next_tick_index),
            frame_index=int(self.frame_index),
            ticks_requested=int(ticks_requested),
            dt_seconds=float(dt),
            tick_dt_seconds=float(self.clock.dt_tick),
            is_networked=False,
            is_replay=False,
            refund_clock=self.clock,
        )
        self.frame_index = int(advance.frame_index)
        self.next_tick_index = int(advance.next_tick_index)
        return self._apply_tick_batch(
            runtime,
            batch=advance.batch,
            session=session,
        )
