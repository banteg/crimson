from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, TypeAlias, cast

from crimson.quest_level import QuestLevel
from grim.rand import CrtRand, RngTraceSink

from ...effects import FxQueue, FxQueueRotated
from ...game_modes import GameMode
from ...quests import quest_by_level
from ...quests.runtime import build_quest_spawn_table
from ...quests.types import QuestContext, QuestDefinition, SpawnEntry
from ...replay import Replay, apply_replay_bootstrap, warn_on_game_version_mismatch
from ...replay.checkpoints import ReplayCheckpoint
from ...replay.checkpoints import build_checkpoint as build_replay_checkpoint
from ...replay.header_settings import session_settings_from_replay_header
from ...replay.input_codec import unpack_tick_inputs
from ...weapon_runtime import weapon_assign_player
from ...weapons import WeaponId
from ..hooks import TickResult
from ..input_providers import ResolvedTick
from ..sessions import (
    DeterministicSession,
    QuestSpawnState,
    RushSpawnState,
    SurvivalSpawnState,
    quest_post_step,
    rush_input_transform,
    rush_mid_step,
    survival_mid_step,
)
from ..world_state import WorldState
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
TickRngTraceObserver: TypeAlias = Callable[[TickResult, tuple[RngTraceDraw, ...]], None]
TickProgressCallback: TypeAlias = Callable[[int], None]
TickBeginObserver: TypeAlias = Callable[
    [int, WorldState, float],
    None,
]
TickEndObserver: TypeAlias = Callable[[TickResult, WorldState], None]


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


@dataclass(slots=True, frozen=True)
class PlaybackWalkHooks:
    before_tick: TickBeginObserver | None = None
    after_tick: TickEndObserver | None = None
    on_progress: TickProgressCallback | None = None
    on_rng_trace: TickRngTraceObserver | None = None


@dataclass(slots=True, frozen=True)
class PlaybackWalkResult:
    start_tick: int
    next_tick_index: int
    ticks_completed: int


@dataclass(slots=True)
class _PlaybackTickMeta:
    tick_index: int
    dt_tick: float
    trace_ctx: object
    tick_rng_rows: list[RngTraceDraw]


class PlaybackDriver:
    """Canonical replay driver."""

    def __init__(
        self,
        replay: Replay,
        *,
        max_ticks: int | None = None,
        trace_rng: bool = False,
        version_mismatch_action: str | None = "verification",
        world_size: float | None = None,
        fx_queue: FxQueue | None = None,
        fx_queue_rotated: FxQueueRotated | None = None,
        inter_tick_rand_draws: int = 0,
        inter_tick_rand_draws_by_tick: dict[int, int] | None = None,
        spawn_entries: tuple[SpawnEntry, ...] | None = None,
        quest_stage_major: int | None = None,
        quest_stage_minor: int | None = None,
        start_weapon_id: WeaponId | None = None,
    ) -> None:
        self.replay = replay
        self.max_ticks = max_ticks
        self.trace_rng = bool(trace_rng)
        self.inter_tick_rand_draws = max(0, int(inter_tick_rand_draws))
        self.inter_tick_rand_draws_by_tick = inter_tick_rand_draws_by_tick
        self._provided_world_size = float(world_size) if world_size is not None else None
        self._provided_fx_queue = fx_queue
        self._provided_fx_queue_rotated = fx_queue_rotated
        self._quest_spawn_entries = tuple(spawn_entries) if spawn_entries is not None else None
        self._quest_stage_major = quest_stage_major
        self._quest_stage_minor = quest_stage_minor
        self._quest_start_weapon_id = start_weapon_id
        self._quest_spawn_state: QuestSpawnState | None = None

        if version_mismatch_action is not None:
            warn_on_game_version_mismatch(replay, action=str(version_mismatch_action))

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
        self.session = self._build_session(apply_world_dt_steps=bool(apply_world_dt_steps))
        self._last_tick_rng_rows: tuple[RngTraceDraw, ...] = ()

        self.tick_limit = (
            len(replay.ticks)
            if self.max_ticks is None
            else min(len(replay.ticks), max(0, int(self.max_ticks)))
        )

    def _resolve_world_size(self) -> float:
        if self._provided_world_size is not None:
            return float(self._provided_world_size)
        return float(self.replay.header.world_size)

    def _prepare_world(self) -> WorldState:
        world = WorldState.build(
            world_size=float(self.world_size),
            demo_mode_active=False,
            hardcore=bool(self.replay.header.hardcore),
            quest_fail_retry_count=int(self.replay.header.quest_fail_retry_count),
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
        if self._provided_fx_queue is not None and self._provided_fx_queue_rotated is not None:
            return self._provided_fx_queue, self._provided_fx_queue_rotated
        return build_empty_fx_queues()

    def _resolve_quest_setup(self) -> tuple[tuple[SpawnEntry, ...], int | None, int | None, WeaponId | None]:
        spawn_entries = self._quest_spawn_entries
        quest_stage_major = self._quest_stage_major
        quest_stage_minor = self._quest_stage_minor
        start_weapon_id = self._quest_start_weapon_id

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

    def _build_session(self, *, apply_world_dt_steps: bool) -> DeterministicSession:
        damage_scale_by_type = build_damage_scale_by_type()
        self._quest_spawn_state = None
        match self.mode_id:
            case GameMode.SURVIVAL:
                survival_spawn = SurvivalSpawnState()
                return DeterministicSession(
                    world=self.world,
                    world_size=float(self.world_size),
                    damage_scale_by_type=damage_scale_by_type,
                    fx_queue=self.fx_queue,
                    fx_queue_rotated=self.fx_queue_rotated,
                    game_mode=GameMode.SURVIVAL,
                    perk_progression_enabled=True,
                    detail_preset=int(self.replay.header.detail_preset),
                    gore_disabled=int(self.replay.header.gore_disabled),
                    game_tune_started=False,
                    apply_world_dt_steps=bool(apply_world_dt_steps),
                    clear_fx_queues_each_tick=True,
                    finalize_post_render_lifecycle=True,
                    mid_step_hook=lambda ctx: survival_mid_step(ctx, survival_spawn),
                )
            case GameMode.RUSH:
                enforce_rush_loadout(self.world)
                rush_spawn = RushSpawnState()
                return DeterministicSession(
                    world=self.world,
                    world_size=float(self.world_size),
                    damage_scale_by_type=damage_scale_by_type,
                    fx_queue=self.fx_queue,
                    fx_queue_rotated=self.fx_queue_rotated,
                    game_mode=GameMode.RUSH,
                    perk_progression_enabled=False,
                    detail_preset=int(self.replay.header.detail_preset),
                    gore_disabled=int(self.replay.header.gore_disabled),
                    game_tune_started=False,
                    clear_fx_queues_each_tick=True,
                    finalize_post_render_lifecycle=True,
                    elapsed_uses_raw_dt=True,
                    mid_step_hook=lambda ctx: rush_mid_step(ctx, rush_spawn),
                    before_step_hook=lambda: enforce_rush_loadout(self.world),
                    input_transform=rush_input_transform,
                )
            case GameMode.QUESTS:
                spawn_entries, quest_stage_major, quest_stage_minor, start_weapon_id = self._resolve_quest_setup()

                if quest_stage_major is not None and quest_stage_minor is not None:
                    self.world.state.quest_level = QuestLevel.from_parts(quest_stage_major, quest_stage_minor)

                weapon_id = start_weapon_id or WeaponId.PISTOL
                if weapon_id <= WeaponId.NONE:
                    weapon_id = WeaponId.PISTOL
                for player in self.world.players:
                    weapon_assign_player(player, weapon_id, state=self.world.state)

                self.world.creatures.capture_spawn_events_authoritative = False

                quest_state = QuestSpawnState(spawn_entries=tuple(spawn_entries))
                self._quest_spawn_state = quest_state

                return DeterministicSession(
                    world=self.world,
                    world_size=float(self.world_size),
                    damage_scale_by_type=damage_scale_by_type,
                    fx_queue=self.fx_queue,
                    fx_queue_rotated=self.fx_queue_rotated,
                    game_mode=GameMode.QUESTS,
                    perk_progression_enabled=True,
                    detail_preset=int(self.replay.header.detail_preset),
                    gore_disabled=int(self.replay.header.gore_disabled),
                    game_tune_started=False,
                    demo_mode_active=bool(self.world.state.demo_mode_active),
                    apply_world_dt_steps=bool(apply_world_dt_steps),
                    clear_fx_queues_each_tick=True,
                    finalize_post_render_lifecycle=True,
                    post_step_hook=lambda ctx: quest_post_step(ctx, quest_state),
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

        if self.inter_tick_rand_draws_by_tick is not None:
            draws = self.inter_tick_rand_draws_by_tick.get(int(tick_index))
            if draws is None:
                draws = int(self.inter_tick_rand_draws)
            for _ in range(max(0, int(draws))):
                state.rng.rand()

        trace_ctx = _tick_rng_trace(state.rng, enabled=bool(self.trace_rng))
        tick_rng_rows = trace_ctx.__enter__()
        return _PlaybackTickMeta(
            tick_index=int(tick_index),
            dt_tick=float(dt_tick),
            trace_ctx=trace_ctx,
            tick_rng_rows=tick_rng_rows,
        )

    def _finalize_tick_result(
        self,
        *,
        tick_result: TickResult,
        meta: _PlaybackTickMeta,
    ) -> TickResult:
        trace_ctx = cast(Any, meta.trace_ctx)
        trace_closed = False
        try:
            source_tick = tick_result.source_tick
            tick_index = int(source_tick.tick_index)
            if int(meta.tick_index) != int(tick_index):
                raise ReplayRunnerError(
                    f"playback tick mismatch: meta={int(meta.tick_index)} runner={int(tick_index)}",
                )

            state = self.world.state

            # Close the trace context before snapshotting rows so any
            # `finally`-recorded draws are included in this tick.
            trace_ctx.__exit__(None, None, None)
            trace_closed = True

            if self.inter_tick_rand_draws_by_tick is None:
                draws = max(0, int(self.inter_tick_rand_draws))
                for _ in range(draws):
                    state.rng.rand()

            self._last_tick_rng_rows = tuple(meta.tick_rng_rows)
            return tick_result
        finally:
            if not trace_closed:
                trace_ctx.__exit__(None, None, None)

    def build_checkpoint(
        self,
        *,
        tick_result: TickResult,
        use_world_step_creature_count: bool = False,
    ) -> ReplayCheckpoint:
        return build_replay_checkpoint(
            tick_index=int(tick_result.source_tick.tick_index),
            world=self.world,
            elapsed_ms=float(self.elapsed_ms),
            creature_count_override=(
                int(tick_result.payload.creature_count_world_step)
                if bool(use_world_step_creature_count)
                else None
            ),
            rng_marks=dict(tick_result.payload.rng_marks),
            deaths=tick_result.payload.step.events.deaths,
            events=tick_result.payload.step.events,
        )

    def step_tick(self, tick_index: int) -> TickResult:
        tick_index = int(tick_index)
        replay_tick = self.replay.ticks[tick_index]
        dt_tick = float(replay_tick.dt)
        meta = self._prepare_tick_meta(tick_index=tick_index, dt_tick=dt_tick)
        self._last_tick_rng_rows = ()

        inputs = unpack_tick_inputs(replay_tick.inputs)
        commands = list(replay_tick.commands)
        source_tick = ResolvedTick(
            tick_index=int(tick_index),
            dt_seconds=float(dt_tick),
            inputs=list(inputs),
            commands=list(commands),
        )

        timing = self.session.timing_for_dt(dt_tick)
        session_tick = self.session.step_tick(
            timing=timing, inputs=inputs,
            trace_rng=self.trace_rng, commands=commands,
        )
        tick_result = TickResult(
            source_tick=source_tick,
            payload=session_tick,
            replay_tick_index=int(tick_index),
        )
        return self._finalize_tick_result(tick_result=tick_result, meta=meta)

    def walk_ticks(
        self,
        *,
        start_tick: int = 0,
        stop_tick: int | None = None,
        hooks: PlaybackWalkHooks | None = None,
    ) -> PlaybackWalkResult:
        requested_start_tick = int(start_tick)
        if requested_start_tick < 0:
            raise ReplayRunnerError(f"invalid start_tick: {requested_start_tick}")
        requested_stop_tick = int(self.tick_limit) if stop_tick is None else int(stop_tick)
        if requested_stop_tick < requested_start_tick:
            raise ReplayRunnerError(
                f"invalid tick range: start_tick={requested_start_tick} stop_tick={requested_stop_tick}",
            )

        tick_limit = int(self.tick_limit)
        next_tick_index = min(requested_start_tick, tick_limit)
        stop_tick_index = min(requested_stop_tick, tick_limit)
        active_hooks = hooks if hooks is not None else PlaybackWalkHooks()

        while next_tick_index < stop_tick_index:
            if active_hooks.before_tick is not None:
                active_hooks.before_tick(
                    int(next_tick_index),
                    self.world,
                    float(self.replay.ticks[next_tick_index].dt),
                )
            tick_result = self.step_tick(next_tick_index)
            next_tick_index = int(tick_result.source_tick.tick_index) + 1

            if active_hooks.after_tick is not None:
                active_hooks.after_tick(tick_result, self.world)
            if active_hooks.on_rng_trace is not None:
                active_hooks.on_rng_trace(tick_result, self._last_tick_rng_rows)
            if active_hooks.on_progress is not None:
                active_hooks.on_progress(int(next_tick_index))

        return PlaybackWalkResult(
            start_tick=min(requested_start_tick, tick_limit),
            next_tick_index=int(next_tick_index),
            ticks_completed=int(next_tick_index - min(requested_start_tick, tick_limit)),
        )

    def run(
        self,
        *,
        hooks: PlaybackWalkHooks | None = None,
    ) -> RunResult:
        self.walk_ticks(
            start_tick=0,
            stop_tick=int(self.tick_limit),
            hooks=hooks,
        )
        return self.build_run_result(ticks=int(self.tick_limit))

    def build_run_result(self, *, ticks: int) -> RunResult:
        shots_fired, shots_hit = player0_shots(self.world.state)
        most_used_weapon_id = player0_most_used_weapon_id(self.world.state, self.world.players)
        score_xp = int(self.world.players[0].experience) if self.world.players else 0

        return RunResult(
            game_mode_id=self.mode_id,
            tick_rate=int(self.tick_rate),
            ticks=int(ticks),
            elapsed_ms=int(self.elapsed_ms),
            score_xp=int(score_xp),
            creature_kill_count=int(self.world.creatures.kill_count),
            most_used_weapon_id=most_used_weapon_id,
            shots_fired=int(shots_fired),
            shots_hit=int(shots_hit),
            rng_state=int(self.world.state.rng.state),
        )

    @property
    def elapsed_ms(self) -> float:
        quest_state = self._quest_spawn_state
        if quest_state is not None:
            return float(quest_state.spawn_timeline_ms)
        return float(self.session.elapsed_ms)

    @property
    def quest_spawn_state(self) -> QuestSpawnState | None:
        return self._quest_spawn_state


def build_verify_playback_driver(
    replay: Replay,
    *,
    max_ticks: int | None = None,
    warn_on_version_mismatch: bool = True,
    trace_rng: bool = False,
    inter_tick_rand_draws: int = 0,
    inter_tick_rand_draws_by_tick: dict[int, int] | None = None,
    spawn_entries: tuple[SpawnEntry, ...] | None = None,
    quest_stage_major: int | None = None,
    quest_stage_minor: int | None = None,
    start_weapon_id: WeaponId | None = None,
) -> PlaybackDriver:
    """Build the canonical headless/verification replay driver."""

    return PlaybackDriver(
        replay,
        max_ticks=max_ticks,
        trace_rng=bool(trace_rng),
        version_mismatch_action=("verification" if bool(warn_on_version_mismatch) else None),
        inter_tick_rand_draws=int(inter_tick_rand_draws),
        inter_tick_rand_draws_by_tick=inter_tick_rand_draws_by_tick,
        spawn_entries=spawn_entries,
        quest_stage_major=quest_stage_major,
        quest_stage_minor=quest_stage_minor,
        start_weapon_id=start_weapon_id,
    )


def build_runtime_playback_driver(
    replay: Replay,
    *,
    max_ticks: int | None,
    trace_rng: bool,
    world_size: float,
    fx_queue: FxQueue,
    fx_queue_rotated: FxQueueRotated,
    spawn_entries: tuple[SpawnEntry, ...] | None = None,
    quest_stage_major: int | None = None,
    quest_stage_minor: int | None = None,
    start_weapon_id: WeaponId | None = None,
) -> PlaybackDriver:
    """Build the canonical live replay-playback driver."""

    return PlaybackDriver(
        replay,
        max_ticks=max_ticks,
        trace_rng=bool(trace_rng),
        version_mismatch_action=None,
        world_size=float(world_size),
        fx_queue=fx_queue,
        fx_queue_rotated=fx_queue_rotated,
        spawn_entries=spawn_entries,
        quest_stage_major=quest_stage_major,
        quest_stage_minor=quest_stage_minor,
        start_weapon_id=start_weapon_id,
    )
