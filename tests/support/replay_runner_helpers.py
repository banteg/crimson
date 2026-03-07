from __future__ import annotations

from collections.abc import Callable

from crimson.game_modes import GameMode
from crimson.quests import quest_by_level
from crimson.quests.level import QuestLevel
from crimson.quests.runtime import build_quest_spawn_table
from crimson.quests.types import QuestContext
from crimson.replay import ReplayHeader, ReplayRecorder
from crimson.replay.checkpoints import ReplayCheckpoint
from crimson.replay.driver.playback_driver import PlaybackWalkHooks, build_verify_playback_driver
from crimson.replay.driver.replay_info import ReplayInfoResult, collect_replay_info
from crimson.replay.driver.setup import RunResult
from crimson.replay.types import current_replay_game_version
from crimson.sim.input import PlayerInput
from crimson.sim.world_state import WorldEvents, WorldState
from grim.geom import Vec2
from grim.rand import Crand


def _blank_survival_replay(
    *, ticks: int, seed: int = 0xBEEF, game_version: str | None = None,
) -> tuple[ReplayHeader, ReplayRecorder]:
    header = ReplayHeader(
        game_mode_id=GameMode.SURVIVAL,
        seed=int(seed),
        tick_rate=60,
        player_count=1,
        game_version=(str(current_replay_game_version()) if game_version is None else str(game_version)),
    )
    rec = ReplayRecorder(header)
    for _ in range(int(ticks)):
        rec.record_tick([PlayerInput(aim=Vec2(512.0, 512.0))])
    return header, rec


def _blank_rush_replay(
    *, ticks: int, seed: int = 0xBEEF, game_version: str | None = None,
) -> tuple[ReplayHeader, ReplayRecorder]:
    header = ReplayHeader(
        game_mode_id=GameMode.RUSH,
        seed=int(seed),
        tick_rate=60,
        player_count=1,
        game_version=(str(current_replay_game_version()) if game_version is None else str(game_version)),
    )
    rec = ReplayRecorder(header)
    for _ in range(int(ticks)):
        rec.record_tick([PlayerInput(aim=Vec2(512.0, 512.0))])
    return header, rec


def _blank_quest_replay(
    *, ticks: int, seed: int = 101, game_version: str | None = None,
) -> tuple[ReplayHeader, ReplayRecorder]:
    header = ReplayHeader(
        game_mode_id=GameMode.QUESTS,
        seed=int(seed),
        quest_level=QuestLevel(1, 1),
        tick_rate=60,
        player_count=1,
        game_version=(str(current_replay_game_version()) if game_version is None else str(game_version)),
    )
    rec = ReplayRecorder(header)
    for _ in range(int(ticks)):
        rec.record_tick([PlayerInput(aim=Vec2(512.0, 512.0))])
    return header, rec


def _quest_spawn_entries(level: str = "1.1", *, player_count: int = 1, seed: int = 101):
    quest = quest_by_level(level)
    assert quest is not None
    ctx = QuestContext(width=1024, height=1024, player_count=int(player_count))
    return build_quest_spawn_table(
        quest,
        ctx,
        rng=Crand(int(seed)),
        hardcore=False,
        full_version=True,
    )


def _run_verify_playback(
    replay,
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
    start_weapon_id=None,
    tick_progress_callback: Callable[[int], None] | None = None,
    tick_observer: Callable[[int, WorldState], None] | None = None,
    tick_trace_observer: Callable[[int, WorldState, float, WorldEvents, dict[str, int]], None] | None = None,
    tick_rng_trace_observer: Callable[[int, list[tuple[int, int, int]]], None] | None = None,
) -> RunResult:
    driver = build_verify_playback_driver(
        replay,
        max_ticks=max_ticks,
        warn_on_version_mismatch=bool(warn_on_version_mismatch),
        trace_rng=bool(trace_rng),
        inter_tick_rand_draws=int(inter_tick_rand_draws),
        inter_tick_rand_draws_by_tick=inter_tick_rand_draws_by_tick,
        spawn_entries=spawn_entries,
        start_weapon_id=start_weapon_id,
    )

    after_tick = None
    if checkpoints_out is not None or tick_trace_observer is not None or tick_observer is not None:
        def _after_tick(tick_result, world) -> None:
            if checkpoints_out is not None and checkpoint_ticks is not None and int(tick_result.source_tick.tick_index) in checkpoint_ticks:
                checkpoints_out.append(
                    driver.build_checkpoint(
                        tick_result=tick_result,
                        use_world_step_creature_count=bool(checkpoint_use_world_step_creature_count),
                    ),
                )
            if tick_trace_observer is not None:
                tick = tick_result.payload
                tick_trace_observer(
                    int(tick_result.source_tick.tick_index),
                    world,
                    float(tick.elapsed_ms),
                    tick.step.events,
                    dict(tick.rng_marks),
                )
            if tick_observer is not None:
                tick_observer(int(tick_result.source_tick.tick_index), world)

        after_tick = _after_tick

    on_rng_trace = None
    if tick_rng_trace_observer is not None:
        def _on_rng_trace(tick_result, draws) -> None:
            tick_rng_trace_observer(
                int(tick_result.source_tick.tick_index),
                list(draws),
            )

        on_rng_trace = _on_rng_trace

    return driver.run(
        hooks=PlaybackWalkHooks(
            after_tick=after_tick,
            on_progress=tick_progress_callback,
            on_rng_trace=on_rng_trace,
        ),
    )


def _collect_verify_replay_info(
    replay,
    *,
    max_ticks: int | None = None,
    player_index: int | None = None,
    include_extra_events: bool = True,
) -> ReplayInfoResult:
    driver = build_verify_playback_driver(
        replay,
        max_ticks=max_ticks,
        warn_on_version_mismatch=True,
        trace_rng=False,
    )
    return collect_replay_info(
        driver,
        player_index=player_index,
        include_extra_events=bool(include_extra_events),
    )
