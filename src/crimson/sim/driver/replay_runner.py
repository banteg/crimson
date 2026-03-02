from __future__ import annotations

from collections.abc import Callable

from ...game_modes import GameMode
from ...replay import Replay
from ...replay.checkpoints import ReplayCheckpoint
from ...weapons import WeaponId
from ..world_state import WorldEvents, WorldState
from .playback_driver import (
    PlaybackDriver,
    PlaybackDriverOptions,
    TickRngTraceObserver,
    dt_ms_overrides_from_replay,
    resolve_quest_level_from_replay,
)
from .setup import ReplayRunnerError, RunResult

__all__ = [
    "ReplayRunnerError",
    "RunResult",
    "TickRngTraceObserver",
    "run_replay",
    "_resolve_quest_level",
]


# Back-compat alias used by replay playback mode.
def _resolve_quest_level(replay: Replay) -> str:
    return resolve_quest_level_from_replay(replay)


def run_replay(
    replay: Replay,
    *,
    max_ticks: int | None = None,
    warn_on_version_mismatch: bool = True,
    strict_events: bool = True,
    trace_rng: bool = False,
    checkpoint_use_world_step_creature_count: bool = False,
    checkpoints_out: list[ReplayCheckpoint] | None = None,
    checkpoint_ticks: set[int] | None = None,
    dt_frame_overrides: dict[int, float] | None = None,
    dt_frame_ms_i32_overrides: dict[int, int] | None = None,
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
    mode_id = int(replay.header.game_mode_id)
    replay_dt_ms_overrides = dt_ms_overrides_from_replay(replay)
    effective_dt_ms_overrides = (
        dt_frame_ms_i32_overrides
        if dt_frame_ms_i32_overrides is not None
        else replay_dt_ms_overrides
    )

    options = PlaybackDriverOptions(
        max_ticks=max_ticks,
        warn_on_version_mismatch=bool(warn_on_version_mismatch),
        version_mismatch_action="verification",
        strict_events=bool(strict_events),
        trace_rng=bool(trace_rng),
        dt_frame_overrides=dt_frame_overrides,
        dt_frame_ms_i32_overrides=effective_dt_ms_overrides,
        inter_tick_rand_draws=int(inter_tick_rand_draws),
        inter_tick_rand_draws_by_tick=inter_tick_rand_draws_by_tick,
        clear_fx_queues_each_tick=True,
        game_tune_started=False,
        survival_partition_events=True,
        quest_partition_events=True,
        defer_menu_open=False,
        rush_force_strict_events=True,
        rush_pass_dt_frame_ms_i32=True,
        rush_enforce_loadout=True,
        quest_manual_finalize_post_render_lifecycle=True,
        quest_disable_capture_spawn_events_authoritative=True,
        quest_finalize_post_render_lifecycle_each_tick=False,
        apply_terminal_tick_events=True,
        terminal_events_use_resolved_dt=(mode_id != int(GameMode.RUSH)),
        quest_result_uses_spawn_timeline_ms=True,
        spawn_entries=spawn_entries,
        quest_stage_major=quest_stage_major,
        quest_stage_minor=quest_stage_minor,
        start_weapon_id=start_weapon_id,
    )

    driver = PlaybackDriver(replay, options)
    return driver.run_to_completion(
        checkpoint_use_world_step_creature_count=bool(checkpoint_use_world_step_creature_count),
        checkpoints_out=checkpoints_out,
        checkpoint_ticks=checkpoint_ticks,
        tick_progress_callback=tick_progress_callback,
        tick_observer=tick_observer,
        tick_trace_observer=tick_trace_observer,
        tick_rng_trace_observer=tick_rng_trace_observer,
    )
