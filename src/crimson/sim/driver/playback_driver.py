from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, TypeAlias, cast

import msgspec

from crimson.quest_level import QuestLevel
from grim.rand import CrtRand, RngTraceSink

from ...effects import FxQueue, FxQueueRotated
from ...game_modes import GameMode
from ...quests import quest_by_level
from ...quests.runtime import build_quest_spawn_table
from ...quests.types import QuestContext, QuestDefinition, SpawnEntry
from ...replay import Replay, apply_replay_bootstrap, warn_on_game_version_mismatch
from ...replay.checkpoints import ReplayCheckpoint, build_checkpoint
from ...replay.header_settings import session_settings_from_replay_header
from ...replay.input_codec import unpack_tick_inputs
from ...weapon_runtime import weapon_assign_player
from ...weapons import WeaponId
from ..hooks import TickResult
from ..input_providers import (
    GameCommand,
)
from ..sessions import (
    DeterministicSession,
    DeterministicSessionTick,
    QuestSpawnState,
    RushSpawnState,
    SurvivalSpawnState,
    quest_post_step,
    rush_input_transform,
    rush_mid_step,
    survival_mid_step,
)
from ..step_pipeline import DeterministicStepResult
from ..world_state import WorldEvents, WorldState
from .replay_timing import should_apply_world_dt_steps_for_replay
from .setup import (
    ReplayRunnerError,
    RunResult,
    build_damage_scale_by_type,
    build_empty_fx_queues,
    player0_most_used_weapon_id,
    player0_shots,
    reset_players,
    status_from_snapshot,
)

RUSH_WEAPON_ID = WeaponId.ASSAULT_RIFLE
RUSH_FORCED_AMMO = 30.0

RngTraceDraw: TypeAlias = tuple[int, int, int]
TickRngTraceObserver: TypeAlias = Callable[[int, list[RngTraceDraw]], None]
TickObserver: TypeAlias = Callable[[int, WorldState], None]
TickTraceObserver: TypeAlias = Callable[[int, WorldState, float, WorldEvents, dict[str, int]], None]
TickProgressCallback: TypeAlias = Callable[[int], None]
TickBeginObserver: TypeAlias = Callable[
    [int, WorldState, float],
    None,
]


def resolve_quest_level_from_replay(replay: Replay) -> str:
    quest_level = QuestLevel.try_parse(str(replay.header.quest_level))
    if quest_level is not None:
        return quest_level.to_string()

    # Legacy replays (e.g. capture-derived) may not encode the quest id. Classic quest RNG
    # seeding uses `major*100 + minor`, so we can often recover the level from `header.seed`.
    seed = int(replay.header.seed)
    major = seed // 100
    minor = seed % 100
    if 1 <= int(major) <= 5 and 1 <= int(minor) <= 10:
        return QuestLevel.from_parts(major, minor).to_string()
    return ""


def resolve_replay_quest_setup(
    replay: Replay,
    *,
    world_size: float,
    player_count: int,
) -> tuple[QuestDefinition, tuple[SpawnEntry, ...]]:
    quest_level = resolve_quest_level_from_replay(replay)
    quest = quest_by_level(quest_level) if quest_level else None
    if quest is None:
        raise ReplayRunnerError(f"unsupported quest replay: unknown quest_level={quest_level!r}")

    ctx = QuestContext(
        width=int(world_size),
        height=int(world_size),
        player_count=int(player_count),
    )
    spawn_entries = tuple(
        build_quest_spawn_table(
            quest,
            ctx,
            seed=int(replay.header.seed),
            hardcore=bool(replay.header.hardcore),
            full_version=True,
        ),
    )
    return quest, spawn_entries


def enforce_rush_loadout(world: WorldState) -> None:
    for player in world.players:
        if player.weapon.weapon_id != RUSH_WEAPON_ID:
            weapon_assign_player(player, RUSH_WEAPON_ID, state=world.state)
        # Native `rush_mode_update` forces assault rifle + 30 ammo every frame.
        player.weapon.ammo = float(RUSH_FORCED_AMMO)


@contextmanager
def _tick_rng_trace(rng: object, *, enabled: bool) -> Iterator[list[RngTraceDraw]]:
    draws: list[RngTraceDraw] = []
    if not enabled or not isinstance(rng, CrtRand):
        yield draws
        return

    previous_sink = rng.trace_sink

    def _sink(state_before_u32: int, state_after_u32: int, value_15: int) -> None:
        draws.append((int(state_before_u32), int(value_15), int(state_after_u32)))

    trace_sink: RngTraceSink = _sink
    rng.set_trace_sink(trace_sink)
    try:
        yield draws
    finally:
        rng.set_trace_sink(previous_sink)


class PlaybackDriverOptions(msgspec.Struct, frozen=True):
    max_ticks: int | None = None
    trace_rng: bool = False
    version_mismatch_action: str | None = "verification"


@dataclass(slots=True, frozen=True)
class PlaybackTimingConfig:
    inter_tick_rand_draws: int = 0
    inter_tick_rand_draws_by_tick: dict[int, int] | None = None


@dataclass(slots=True, frozen=True)
class PlaybackWorldConfig:
    world: WorldState | None = None
    world_size: float | None = None
    fx_queue: FxQueue | None = None
    fx_queue_rotated: FxQueueRotated | None = None
    use_existing_world_state: bool = False


@dataclass(slots=True, frozen=True)
class PlaybackSessionDefaults:
    clear_fx_queues_each_tick: bool = True
    game_tune_started: bool = False


@dataclass(slots=True, frozen=True)
class QuestSessionConfig:
    disable_capture_spawn_events_authoritative: bool = True
    result_uses_spawn_timeline_ms: bool = True
    spawn_entries: tuple[SpawnEntry, ...] | None = None
    quest_stage_major: int | None = None
    quest_stage_minor: int | None = None
    start_weapon_id: WeaponId | None = None


@dataclass(slots=True, frozen=True)
class PlaybackDriverConfig:
    timing: PlaybackTimingConfig = field(default_factory=PlaybackTimingConfig)
    world: PlaybackWorldConfig = field(default_factory=PlaybackWorldConfig)
    session_defaults: PlaybackSessionDefaults = field(default_factory=PlaybackSessionDefaults)
    quest: QuestSessionConfig = field(default_factory=QuestSessionConfig)


@dataclass(slots=True)
class PlaybackTickOutcome:
    tick_index: int
    dt_tick: float
    commands: list[GameCommand]
    world: WorldState
    step: DeterministicStepResult
    elapsed_ms: float
    rng_marks: dict[str, int]
    creature_count_world_step: int
    tick_rng_rows: list[RngTraceDraw]
    spawn_timeline_ms: float | None = None
    completion_transition_ms: float | None = None
    play_hit_sfx: bool = False
    play_completion_music: bool = False


@dataclass(slots=True)
class _PlaybackTickMeta:
    tick_index: int
    dt_tick: float
    trace_ctx: object
    tick_rng_rows: list[RngTraceDraw]


@dataclass(slots=True)
class SimplePlaybackRuntime:
    """Playback runtime for game modes without extra per-tick enrichment (survival, rush)."""

    session: DeterministicSession

    def enrich_tick_outcome(self, outcome: PlaybackTickOutcome, *, tick: DeterministicSessionTick) -> None:
        _ = outcome, tick

    def checkpoint_elapsed_ms(self, outcome: PlaybackTickOutcome) -> float:
        return float(outcome.elapsed_ms)

    def run_result_elapsed_ms(self) -> int:
        return int(self.session.elapsed_ms)


@dataclass(slots=True)
class QuestPlaybackRuntime:
    session: DeterministicSession
    quest_state: QuestSpawnState
    result_uses_spawn_timeline_ms: bool

    def enrich_tick_outcome(self, outcome: PlaybackTickOutcome, *, tick: DeterministicSessionTick) -> None:
        _ = tick
        outcome.spawn_timeline_ms = float(self.quest_state.spawn_timeline_ms)
        outcome.completion_transition_ms = float(self.quest_state.completion_transition_ms)
        outcome.play_hit_sfx = bool(self.quest_state.play_hit_sfx)
        outcome.play_completion_music = bool(self.quest_state.play_completion_music)

    def checkpoint_elapsed_ms(self, outcome: PlaybackTickOutcome) -> float:
        if outcome.spawn_timeline_ms is not None:
            return float(outcome.spawn_timeline_ms)
        return float(outcome.elapsed_ms)

    def run_result_elapsed_ms(self) -> int:
        if bool(self.result_uses_spawn_timeline_ms):
            return int(self.quest_state.spawn_timeline_ms)
        return int(self.session.elapsed_ms)


PlaybackModeRuntime: TypeAlias = SimplePlaybackRuntime | QuestPlaybackRuntime


class PlaybackDriver:
    def __init__(
        self,
        replay: Replay,
        pipeline_options: PlaybackDriverOptions,
        *,
        config: PlaybackDriverConfig | None = None,
    ) -> None:
        self.replay = replay
        self.options = pipeline_options
        self.config = config if config is not None else PlaybackDriverConfig()

        if self.options.version_mismatch_action is not None:
            warn_on_game_version_mismatch(replay, action=str(self.options.version_mismatch_action))

        self.session_settings = session_settings_from_replay_header(replay.header)

        mode_raw = int(self.session_settings.mode_id)
        try:
            self.mode_id = GameMode(mode_raw)
        except ValueError as exc:
            raise ReplayRunnerError(f"unsupported replay game_mode_id={mode_raw}") from exc

        tick_rate = int(self.session_settings.tick_rate)
        if tick_rate <= 0:
            raise ReplayRunnerError(f"invalid tick_rate: {tick_rate}")
        self.tick_rate = int(tick_rate)
        self.dt = 1.0 / float(self.tick_rate)

        self.world_size = self._resolve_world_size()
        self.world = self._prepare_world()
        self.fx_queue, self.fx_queue_rotated = self._resolve_fx_queues()

        apply_world_dt_steps = should_apply_world_dt_steps_for_replay(
            original_capture_replay=False,
        )
        self._mode_runtime = self._build_mode_runtime(apply_world_dt_steps=bool(apply_world_dt_steps))
        self.session: DeterministicSession = self._mode_runtime.session

        self.tick_limit = (
            len(replay.ticks)
            if self.options.max_ticks is None
            else min(len(replay.ticks), max(0, int(self.options.max_ticks)))
        )

    def _resolve_world_size(self) -> float:
        world_size = self.config.world.world_size
        if world_size is not None:
            return float(world_size)
        return float(self.replay.header.world_size)

    def _prepare_world(self) -> WorldState:
        world_config = self.config.world
        if bool(world_config.use_existing_world_state):
            world = world_config.world
            if world is None:
                raise ReplayRunnerError(
                    "PlaybackWorldConfig.world is required when use_existing_world_state=True",
                )
            return world

        world = WorldState.build(
            world_size=float(self.world_size),
            demo_mode_active=False,
            hardcore=bool(self.replay.header.hardcore),
            difficulty_level=int(self.replay.header.difficulty_level),
            preserve_bugs=bool(self.session_settings.preserve_bugs),
        )
        reset_players(
            world.players,
            state=world.state,
            world_size=float(self.world_size),
            player_count=int(self.session_settings.player_count),
        )
        world.state.status = status_from_snapshot(
            quest_unlock_index=int(self.replay.header.status.quest_unlock_index),
            quest_unlock_index_full=int(self.replay.header.status.quest_unlock_index_full),
            weapon_usage_counts=self.replay.header.status.weapon_usage_counts,
        )

        if self.mode_id in (GameMode.SURVIVAL, GameMode.RUSH):
            apply_replay_bootstrap(
                self.replay.header,
                rng=world.state.rng,
                world_size=float(self.world_size),
            )
        else:
            world.state.rng.srand(int(self.replay.header.seed))

        return world

    def _resolve_fx_queues(self) -> tuple[FxQueue, FxQueueRotated]:
        world_config = self.config.world
        if world_config.fx_queue is not None and world_config.fx_queue_rotated is not None:
            return world_config.fx_queue, world_config.fx_queue_rotated
        return build_empty_fx_queues()

    def _resolve_quest_setup(
        self,
        quest_config: QuestSessionConfig,
    ) -> tuple[tuple[SpawnEntry, ...], int | None, int | None, WeaponId | None]:
        spawn_entries = quest_config.spawn_entries
        quest_stage_major = quest_config.quest_stage_major
        quest_stage_minor = quest_config.quest_stage_minor
        start_weapon_id = quest_config.start_weapon_id

        if spawn_entries is None:
            quest, spawn_entries = resolve_replay_quest_setup(
                self.replay,
                world_size=float(self.world_size),
                player_count=int(self.session_settings.player_count),
            )

            if quest_stage_major is None or quest_stage_minor is None:
                quest_stage_major, quest_stage_minor = quest.level_key
            if start_weapon_id is None:
                start_weapon_id = quest.start_weapon_id
        else:
            spawn_entries = tuple(spawn_entries)

        return spawn_entries, quest_stage_major, quest_stage_minor, start_weapon_id

    def _build_mode_runtime(self, *, apply_world_dt_steps: bool) -> PlaybackModeRuntime:
        damage_scale_by_type = build_damage_scale_by_type()
        defaults = self.config.session_defaults
        match self.mode_id:
            case GameMode.SURVIVAL:
                survival_spawn = SurvivalSpawnState()
                session = DeterministicSession(
                    world=self.world,
                    world_size=float(self.world_size),
                    damage_scale_by_type=damage_scale_by_type,
                    fx_queue=self.fx_queue,
                    fx_queue_rotated=self.fx_queue_rotated,
                    game_mode=GameMode.SURVIVAL,
                    perk_progression_enabled=True,
                    detail_preset=int(self.replay.header.detail_preset),
                    gore_disabled=int(self.replay.header.gore_disabled),
                    game_tune_started=bool(defaults.game_tune_started),
                    apply_world_dt_steps=bool(apply_world_dt_steps),
                    clear_fx_queues_each_tick=bool(defaults.clear_fx_queues_each_tick),
                    finalize_post_render_lifecycle=True,
                    mid_step_hook=lambda ctx: survival_mid_step(ctx, survival_spawn),
                )
                return SimplePlaybackRuntime(
                    session=session,
                )
            case GameMode.RUSH:
                enforce_rush_loadout(self.world)
                rush_spawn = RushSpawnState()
                session = DeterministicSession(
                    world=self.world,
                    world_size=float(self.world_size),
                    damage_scale_by_type=damage_scale_by_type,
                    fx_queue=self.fx_queue,
                    fx_queue_rotated=self.fx_queue_rotated,
                    game_mode=GameMode.RUSH,
                    perk_progression_enabled=False,
                    detail_preset=int(self.replay.header.detail_preset),
                    gore_disabled=int(self.replay.header.gore_disabled),
                    game_tune_started=bool(defaults.game_tune_started),
                    clear_fx_queues_each_tick=bool(defaults.clear_fx_queues_each_tick),
                    finalize_post_render_lifecycle=True,
                    elapsed_uses_raw_dt=True,
                    mid_step_hook=lambda ctx: rush_mid_step(ctx, rush_spawn),
                    before_step_hook=lambda: enforce_rush_loadout(self.world),
                    input_transform=rush_input_transform,
                )
                return SimplePlaybackRuntime(
                    session=session,
                )
            case GameMode.QUESTS:
                quest_config = self.config.quest
                spawn_entries, quest_stage_major, quest_stage_minor, start_weapon_id = self._resolve_quest_setup(
                    quest_config,
                )

                if quest_stage_major is not None and quest_stage_minor is not None:
                    self.world.state.quest_level = QuestLevel.from_parts(quest_stage_major, quest_stage_minor)

                weapon_id = start_weapon_id or WeaponId.PISTOL
                if weapon_id <= WeaponId.NONE:
                    weapon_id = WeaponId.PISTOL
                for player in self.world.players:
                    weapon_assign_player(player, weapon_id, state=self.world.state)

                if bool(quest_config.disable_capture_spawn_events_authoritative):
                    self.world.creatures.capture_spawn_events_authoritative = False

                quest_state = QuestSpawnState(spawn_entries=tuple(spawn_entries))

                session = DeterministicSession(
                    world=self.world,
                    world_size=float(self.world_size),
                    damage_scale_by_type=damage_scale_by_type,
                    fx_queue=self.fx_queue,
                    fx_queue_rotated=self.fx_queue_rotated,
                    game_mode=GameMode.QUESTS,
                    perk_progression_enabled=True,
                    detail_preset=int(self.replay.header.detail_preset),
                    gore_disabled=int(self.replay.header.gore_disabled),
                    game_tune_started=bool(defaults.game_tune_started),
                    demo_mode_active=bool(self.world.state.demo_mode_active),
                    apply_world_dt_steps=bool(apply_world_dt_steps),
                    clear_fx_queues_each_tick=bool(defaults.clear_fx_queues_each_tick),
                    finalize_post_render_lifecycle=True,
                    post_step_hook=lambda ctx: quest_post_step(ctx, quest_state),
                )
                return QuestPlaybackRuntime(
                    session=session,
                    quest_state=quest_state,
                    result_uses_spawn_timeline_ms=bool(quest_config.result_uses_spawn_timeline_ms),
                )
            case _:
                raise ReplayRunnerError(f"unsupported replay game_mode_id={int(self.mode_id)}")

    def _prepare_tick_meta(
        self,
        *,
        tick_index: int,
        dt_tick: float,
    ) -> _PlaybackTickMeta:
        if int(tick_index) < 0 or int(tick_index) >= int(self.tick_limit):
            raise ReplayRunnerError(f"tick_index out of range: {tick_index} (tick_limit={self.tick_limit})")

        state = self.world.state
        state.game_mode = self.mode_id
        state.demo_mode_active = False

        timing = self.config.timing
        if timing.inter_tick_rand_draws_by_tick is not None:
            draws = timing.inter_tick_rand_draws_by_tick.get(int(tick_index))
            if draws is None:
                draws = int(timing.inter_tick_rand_draws)
            for _ in range(max(0, int(draws))):
                state.rng.rand()

        trace_ctx = _tick_rng_trace(state.rng, enabled=bool(self.options.trace_rng))
        tick_rng_rows = trace_ctx.__enter__()
        return _PlaybackTickMeta(
            tick_index=int(tick_index),
            dt_tick=float(dt_tick),
            trace_ctx=trace_ctx,
            tick_rng_rows=tick_rng_rows,
        )

    def _finalize_tick_outcome(
        self,
        *,
        tick_result: TickResult,
        meta: _PlaybackTickMeta,
    ) -> PlaybackTickOutcome:
        trace_ctx = cast(Any, meta.trace_ctx)
        trace_closed = False
        try:
            tick_index = int(tick_result.tick_index)
            if int(meta.tick_index) != int(tick_index):
                raise ReplayRunnerError(
                    f"playback tick mismatch: meta={int(meta.tick_index)} runner={int(tick_index)}",
                )

            state = self.world.state
            tick = tick_result.payload
            step = tick.step

            # Close the trace context before snapshotting rows so any
            # `finally`-recorded draws are included in this tick.
            trace_ctx.__exit__(None, None, None)
            trace_closed = True

            timing = self.config.timing
            if timing.inter_tick_rand_draws_by_tick is None:
                draws = max(0, int(timing.inter_tick_rand_draws))
                for _ in range(draws):
                    state.rng.rand()

            outcome = PlaybackTickOutcome(
                tick_index=int(tick_index),
                dt_tick=float(meta.dt_tick),
                commands=tick_result.commands,
                world=self.world,
                step=step,
                elapsed_ms=float(tick.elapsed_ms),
                rng_marks=dict(tick.rng_marks),
                creature_count_world_step=int(tick.creature_count_world_step),
                tick_rng_rows=list(meta.tick_rng_rows),
            )
            self._mode_runtime.enrich_tick_outcome(outcome, tick=tick)
            return outcome
        finally:
            if not trace_closed:
                trace_ctx.__exit__(None, None, None)

    def _append_checkpoint_for_tick(
        self,
        *,
        outcome: PlaybackTickOutcome,
        checkpoints_out: list[ReplayCheckpoint],
        checkpoint_use_world_step_creature_count: bool,
    ) -> None:
        checkpoint_rng_marks = dict(outcome.rng_marks)

        checkpoints_out.append(
            build_checkpoint(
                tick_index=int(outcome.tick_index),
                world=self.world,
                elapsed_ms=float(self._mode_runtime.checkpoint_elapsed_ms(outcome)),
                creature_count_override=(
                    int(outcome.creature_count_world_step)
                    if bool(checkpoint_use_world_step_creature_count)
                    else None
                ),
                rng_marks=checkpoint_rng_marks,
                deaths=outcome.step.events.deaths,
                events=outcome.step.events,
            ),
        )

    def step_tick(self, tick_index: int) -> PlaybackTickOutcome:
        tick_index = int(tick_index)
        replay_tick = self.replay.ticks[tick_index]
        dt_tick = float(replay_tick.dt)
        meta = self._prepare_tick_meta(tick_index=tick_index, dt_tick=dt_tick)

        inputs = unpack_tick_inputs(replay_tick.inputs)
        commands = list(replay_tick.commands)

        timing = self.session.timing_for_dt(dt_tick)
        session_tick = self.session.step_tick(
            timing=timing, inputs=inputs,
            trace_rng=self.options.trace_rng, commands=commands,
        )
        tick_result = TickResult(
            tick_index=tick_index,
            payload=session_tick, inputs=inputs, commands=commands,
        )
        return self._finalize_tick_outcome(tick_result=tick_result, meta=meta)

    def run_to_completion(
        self,
        *,
        checkpoint_use_world_step_creature_count: bool = False,
        checkpoints_out: list[ReplayCheckpoint] | None = None,
        checkpoint_ticks: set[int] | None = None,
        tick_progress_callback: TickProgressCallback | None = None,
        tick_observer: TickObserver | None = None,
        tick_trace_observer: TickTraceObserver | None = None,
        tick_rng_trace_observer: TickRngTraceObserver | None = None,
        tick_begin_observer: TickBeginObserver | None = None,
        tick_end_observer: Callable[[PlaybackTickOutcome], None] | None = None,
    ) -> RunResult:
        tick_limit = int(self.tick_limit)
        for tick_index in range(tick_limit):
            if tick_begin_observer is not None:
                tick_begin_observer(
                    int(tick_index),
                    self.world,
                    float(self.replay.ticks[tick_index].dt),
                )
            outcome = self.step_tick(tick_index)

            if tick_rng_trace_observer is not None:
                tick_rng_trace_observer(int(outcome.tick_index), list(outcome.tick_rng_rows))

            if checkpoints_out is not None and checkpoint_ticks is not None and int(outcome.tick_index) in checkpoint_ticks:
                self._append_checkpoint_for_tick(
                    outcome=outcome,
                    checkpoints_out=checkpoints_out,
                    checkpoint_use_world_step_creature_count=bool(checkpoint_use_world_step_creature_count),
                )

            if tick_trace_observer is not None:
                tick_trace_observer(
                    int(outcome.tick_index),
                    self.world,
                    float(outcome.elapsed_ms),
                    outcome.step.events,
                    dict(outcome.rng_marks),
                )

            if tick_observer is not None:
                tick_observer(int(outcome.tick_index), self.world)

            if tick_end_observer is not None:
                tick_end_observer(outcome)

            if tick_progress_callback is not None:
                tick_progress_callback(int(outcome.tick_index) + 1)

        return self.build_run_result(ticks=int(tick_limit))

    def build_run_result(self, *, ticks: int) -> RunResult:
        shots_fired, shots_hit = player0_shots(self.world.state)
        most_used_weapon_id = player0_most_used_weapon_id(self.world.state, self.world.players)
        score_xp = int(self.world.players[0].experience) if self.world.players else 0

        return RunResult(
            game_mode_id=self.mode_id,
            tick_rate=int(self.tick_rate),
            ticks=int(ticks),
            elapsed_ms=int(self._mode_runtime.run_result_elapsed_ms()),
            score_xp=int(score_xp),
            creature_kill_count=int(self.world.creatures.kill_count),
            most_used_weapon_id=most_used_weapon_id,
            shots_fired=int(shots_fired),
            shots_hit=int(shots_hit),
            rng_state=int(self.world.state.rng.state),
        )

    @property
    def survival_session(self) -> DeterministicSession | None:
        if self.mode_id == GameMode.SURVIVAL and isinstance(self.session, DeterministicSession):
            return self.session
        return None

    @property
    def rush_session(self) -> DeterministicSession | None:
        if self.mode_id == GameMode.RUSH and isinstance(self.session, DeterministicSession):
            return self.session
        return None

    @property
    def quest_session(self) -> DeterministicSession | None:
        if self.mode_id == GameMode.QUESTS and isinstance(self.session, DeterministicSession):
            return self.session
        return None
