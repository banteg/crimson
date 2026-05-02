from __future__ import annotations

from crimson.game_modes import GameMode
from crimson.quests import quest_by_level
from crimson.quests.level import QuestLevel
from crimson.quests.runtime import build_quest_spawn_table
from crimson.quests.types import QuestContext
from crimson.replay import ReplayHeader, ReplayRecorder
from crimson.replay.checkpoints import ReplayCheckpoint
from crimson.replay.driver.playback_driver import (
    PlaybackDriver,
    PlaybackWalkObserver,
    RngTraceDraw,
    build_verify_playback_driver,
)
from crimson.replay.driver.replay_info import ReplayInfoResult, collect_replay_info
from crimson.replay.driver.setup import RunResult
from crimson.replay.types import current_replay_game_version
from crimson.sim.hooks import TickResult
from crimson.sim.input import PlayerInput
from crimson.sim.world_state import WorldState
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


def _blank_typo_replay(
    *,
    ticks: int,
    seed: int = 0xBEEF,
    game_version: str | None = None,
    typo_dictionary_words: tuple[str, ...] = (),
    typo_highscore_names: tuple[str, ...] = (),
) -> tuple[ReplayHeader, ReplayRecorder]:
    header = ReplayHeader(
        game_mode_id=GameMode.TYPO,
        seed=int(seed),
        tick_rate=60,
        player_count=1,
        game_version=(str(current_replay_game_version()) if game_version is None else str(game_version)),
        typo_dictionary_words=tuple(typo_dictionary_words),
        typo_highscore_names=tuple(typo_highscore_names),
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


def _blank_tutorial_replay(
    *, ticks: int, seed: int = 0xBEEF, game_version: str | None = None,
) -> tuple[ReplayHeader, ReplayRecorder]:
    header = ReplayHeader(
        game_mode_id=GameMode.TUTORIAL,
        seed=int(seed),
        tick_rate=60,
        player_count=1,
        game_version=(str(current_replay_game_version()) if game_version is None else str(game_version)),
    )
    rec = ReplayRecorder(header)
    for _ in range(int(ticks)):
        rec.record_tick([PlayerInput(aim=Vec2(512.0, 512.0))])
    return header, rec


def _quest_spawn_entries(level: str = "1.1", *, player_count: int = 1, seed: int = 101):
    quest = quest_by_level(QuestLevel.parse(level))
    assert quest is not None
    ctx = QuestContext(width=1024, height=1024, player_count=int(player_count))
    return build_quest_spawn_table(
        quest,
        ctx,
        rng=Crand(int(seed)),
        hardcore=False,
        full_version=True,
    )


class ReplayRngTraceRecorder(PlaybackWalkObserver):
    rows_by_tick: dict[int, list[RngTraceDraw]]

    def rng_trace(self, tick_result: TickResult, draws: tuple[RngTraceDraw, ...]) -> None:
        self.rows_by_tick[int(tick_result.source_tick.tick_index)] = list(draws)


class _VerifyPlaybackObserver(PlaybackWalkObserver):
    driver: PlaybackDriver
    checkpoints_out: list[ReplayCheckpoint] | None = None
    checkpoint_ticks: set[int] | None = None
    checkpoint_use_world_step_creature_count: bool = False
    observer: PlaybackWalkObserver | None = None

    def before_tick(self, tick_index: int, world: WorldState, dt_tick: float) -> None:
        if self.observer is not None:
            self.observer.before_tick(int(tick_index), world, float(dt_tick))

    def after_tick(self, tick_result: TickResult, world: WorldState) -> None:
        checkpoints_out = self.checkpoints_out
        checkpoint_ticks = self.checkpoint_ticks
        tick_index = int(tick_result.source_tick.tick_index)
        if checkpoints_out is not None and checkpoint_ticks is not None and tick_index in checkpoint_ticks:
            checkpoints_out.append(
                self.driver.build_checkpoint(
                    tick_result=tick_result,
                    use_world_step_creature_count=bool(self.checkpoint_use_world_step_creature_count),
                ),
            )
        if self.observer is not None:
            self.observer.after_tick(tick_result, world)

    def rng_trace(self, tick_result: TickResult, draws: tuple[RngTraceDraw, ...]) -> None:
        if self.observer is not None:
            self.observer.rng_trace(tick_result, draws)

    def progress(self, next_tick_index: int) -> None:
        if self.observer is not None:
            self.observer.progress(int(next_tick_index))


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
    observer: PlaybackWalkObserver | None = None,
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

    return driver.run(
        observer=_VerifyPlaybackObserver(
            driver=driver,
            checkpoints_out=checkpoints_out,
            checkpoint_ticks=checkpoint_ticks,
            checkpoint_use_world_step_creature_count=bool(checkpoint_use_world_step_creature_count),
            observer=observer,
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
