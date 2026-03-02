from __future__ import annotations

from collections.abc import Callable

from ...game_modes import GameMode
from ...replay import Replay
from ...replay.checkpoints import ReplayCheckpoint
from ...weapons import WeaponId
from ..world_state import WorldEvents, WorldState
from .playback_driver import (
    PlaybackDriver,
    PlaybackDriverConfig,
    PlaybackDriverOptions,
    PlaybackEventConfig,
    PlaybackSessionConfigs,
    PlaybackSessionDefaults,
    PlaybackTimingConfig,
    QuestSessionConfig,
    RushSessionConfig,
    SurvivalSessionConfig,
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
    mode_raw = int(replay.header.game_mode_id)
    try:
        mode_id: GameMode | int = GameMode(mode_raw)
    except ValueError:
        mode_id = mode_raw
    match mode_id:
        case GameMode.RUSH:
            terminal_events_use_resolved_dt = False
        case _:
            terminal_events_use_resolved_dt = True

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
        events=PlaybackEventConfig(
            defer_menu_open=False,
            apply_terminal_tick_events=True,
            terminal_events_use_resolved_dt=terminal_events_use_resolved_dt,
        ),
        session_defaults=PlaybackSessionDefaults(
            clear_fx_queues_each_tick=True,
            game_tune_started=False,
        ),
        sessions=PlaybackSessionConfigs(
            survival=SurvivalSessionConfig(partition_events=True),
            rush=RushSessionConfig(
                enforce_loadout=True,
            ),
            quest=QuestSessionConfig(
                partition_events=True,
                disable_capture_spawn_events_authoritative=True,
                finalize_post_render_lifecycle_each_tick=True,
                result_uses_spawn_timeline_ms=True,
                spawn_entries=spawn_entries,
                quest_stage_major=quest_stage_major,
                quest_stage_minor=quest_stage_minor,
                start_weapon_id=start_weapon_id,
            ),
        ),
    )

    driver = PlaybackDriver(replay, options, config=config)
    return driver.run_to_completion(
        checkpoint_use_world_step_creature_count=bool(checkpoint_use_world_step_creature_count),
        checkpoints_out=checkpoints_out,
        checkpoint_ticks=checkpoint_ticks,
        tick_progress_callback=tick_progress_callback,
        tick_observer=tick_observer,
        tick_trace_observer=tick_trace_observer,
        tick_rng_trace_observer=tick_rng_trace_observer,
    )
