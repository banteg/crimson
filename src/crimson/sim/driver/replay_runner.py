from __future__ import annotations

from collections.abc import Callable

from ...replay import Replay
from ...replay.checkpoints import ReplayCheckpoint
from ...weapons import WeaponId
from ..world_state import WorldEvents, WorldState
from .playback_driver import (
    PlaybackDriver,
    PlaybackDriverConfig,
    PlaybackDriverOptions,
    PlaybackSessionDefaults,
    PlaybackTickOutcome,
    PlaybackTimingConfig,
    PlaybackWalkHooks,
    QuestSessionConfig,
    TickRngTraceObserver,
)
from .setup import ReplayRunnerError, RunResult

__all__ = [
    "ReplayRunnerError",
    "RunResult",
    "TickRngTraceObserver",
    "run_replay",
]


def run_replay(
    replay: Replay,
    *,
    max_ticks: int | None = None,
    warn_on_version_mismatch: bool = True,
    trace_rng: bool = False,
    checkpoint_use_world_step_creature_count: bool = False,
    checkpoints_out: list[ReplayCheckpoint] | None = None,
    checkpoint_ticks: set[int] | None = None,
    inter_tick_rand_draws: int = 0,
    inter_tick_rand_draws_by_tick: dict[int, int] | None = None,
    spawn_entries=None,
    quest_stage_major: int | None = None,
    quest_stage_minor: int | None = None,
    start_weapon_id: WeaponId | None = None,
    tick_progress_callback: Callable[[int], None] | None = None,
    tick_observer: Callable[[int, WorldState], None] | None = None,
    tick_trace_observer: Callable[[int, WorldState, float, WorldEvents, dict[str, int]], None] | None = None,
    tick_rng_trace_observer: TickRngTraceObserver | None = None,
) -> RunResult:
    options = PlaybackDriverOptions(
        max_ticks=max_ticks,
        trace_rng=bool(trace_rng),
        version_mismatch_action=("verification" if bool(warn_on_version_mismatch) else None),
    )
    config = PlaybackDriverConfig(
        timing=PlaybackTimingConfig(
            inter_tick_rand_draws=int(inter_tick_rand_draws),
            inter_tick_rand_draws_by_tick=inter_tick_rand_draws_by_tick,
        ),
        session_defaults=PlaybackSessionDefaults(
            clear_fx_queues_each_tick=True,
            game_tune_started=False,
        ),
        quest=QuestSessionConfig(
            disable_capture_spawn_events_authoritative=True,
            result_uses_spawn_timeline_ms=True,
            spawn_entries=spawn_entries,
            quest_stage_major=quest_stage_major,
            quest_stage_minor=quest_stage_minor,
            start_weapon_id=start_weapon_id,
        ),
    )

    driver = PlaybackDriver(replay, options, config=config)
    after_tick = None
    if (
        tick_rng_trace_observer is not None
        or checkpoints_out is not None
        or tick_trace_observer is not None
        or tick_observer is not None
    ):
        def _after_tick(outcome: PlaybackTickOutcome) -> None:
            if tick_rng_trace_observer is not None:
                tick_rng_trace_observer(int(outcome.tick_index), list(outcome.tick_rng_rows))

            if checkpoints_out is not None and checkpoint_ticks is not None and int(outcome.tick_index) in checkpoint_ticks:
                checkpoints_out.append(
                    driver.build_checkpoint(
                        outcome=outcome,
                        use_world_step_creature_count=bool(checkpoint_use_world_step_creature_count),
                    ),
                )

            if tick_trace_observer is not None:
                tick_trace_observer(
                    int(outcome.tick_index),
                    outcome.world,
                    float(outcome.elapsed_ms),
                    outcome.step.events,
                    dict(outcome.rng_marks),
                )

            if tick_observer is not None:
                tick_observer(int(outcome.tick_index), outcome.world)

        after_tick = _after_tick

    return driver.run(
        hooks=PlaybackWalkHooks(
            after_tick=after_tick,
            on_progress=tick_progress_callback,
        ),
    )
