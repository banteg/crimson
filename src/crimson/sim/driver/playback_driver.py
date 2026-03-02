from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TypeAlias

import msgspec

from grim.rand import CrtRand, RngTraceSink

from ...effects import FxQueue, FxQueueRotated
from ...game_modes import GameMode
from ...quests import quest_by_level
from ...quests.runtime import build_quest_spawn_table
from ...quests.types import QuestContext, SpawnEntry
from ...replay import Replay, apply_replay_bootstrap, unpack_tick_inputs, warn_on_game_version_mismatch
from ...replay.checkpoints import ReplayCheckpoint, build_checkpoint
from ...weapon_runtime import weapon_assign_player
from ...weapons import WeaponId
from ..sessions import (
    DeterministicSession,
    DeterministicSessionStepTick,
    QuestDeterministicSession,
    QuestDeterministicSessionTick,
    RushDeterministicSession,
    SurvivalDeterministicSession,
)
from ..step_pipeline import DeterministicStepResult
from ..world_state import WorldEvents, WorldState
from .replay_events import apply_replay_tick_events, partition_tick_events
from .replay_timing import resolve_dt_frame, resolve_dt_frame_ms_i32, should_apply_world_dt_steps_for_replay
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
TickBeginObserver: TypeAlias = Callable[[int, WorldState, float, list[object], list[object], list[object]], None]


def dt_ms_overrides_from_replay(replay: Replay) -> dict[int, int] | None:
    dt_rows = replay.dt_ms_i32
    if not dt_rows:
        return None
    out: dict[int, int] = {}
    for tick_index, dt_ms in enumerate(dt_rows):
        dt_i32 = int(dt_ms)
        if dt_i32 <= 0:
            continue
        out[int(tick_index)] = int(dt_i32)
    return out if out else None


def resolve_quest_level_from_replay(replay: Replay) -> str:
    quest_level = str(replay.header.quest_level)
    if quest_level:
        return str(quest_level)

    # Legacy replays (e.g. capture-derived) may not encode the quest id. Classic quest RNG
    # seeding uses `major*100 + minor`, so we can often recover the level from `header.seed`.
    seed = int(replay.header.seed)
    major = seed // 100
    minor = seed % 100
    if 1 <= int(major) <= 5 and 1 <= int(minor) <= 10:
        return f"{major}.{minor}"
    return ""


def enforce_rush_loadout(world: WorldState) -> None:
    for player in world.players:
        if player.weapon.weapon_id != RUSH_WEAPON_ID:
            weapon_assign_player(player, RUSH_WEAPON_ID)
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
    dt_frame_overrides: dict[int, float] | None = None
    dt_frame_ms_i32_overrides: dict[int, int] | None = None
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
class PlaybackEventConfig:
    strict_events: bool = True
    defer_menu_open: bool = False
    apply_terminal_tick_events: bool = True
    terminal_events_use_resolved_dt: bool = True


@dataclass(slots=True, frozen=True)
class PlaybackSessionDefaults:
    clear_fx_queues_each_tick: bool = True
    game_tune_started: bool = False


@dataclass(slots=True, frozen=True)
class SurvivalSessionConfig:
    partition_events: bool = True


@dataclass(slots=True, frozen=True)
class RushSessionConfig:
    strict_events_override: bool | None = True
    enforce_loadout: bool = True
    use_dt_frame_ms_i32: bool = True


@dataclass(slots=True, frozen=True)
class QuestSessionConfig:
    partition_events: bool = True
    disable_capture_spawn_events_authoritative: bool = True
    finalize_post_render_lifecycle_each_tick: bool = True
    result_uses_spawn_timeline_ms: bool = True
    spawn_entries: tuple[SpawnEntry, ...] | None = None
    quest_stage_major: int | None = None
    quest_stage_minor: int | None = None
    start_weapon_id: WeaponId | None = None


@dataclass(slots=True, frozen=True)
class PlaybackSessionConfigs:
    survival: SurvivalSessionConfig = field(default_factory=SurvivalSessionConfig)
    rush: RushSessionConfig = field(default_factory=RushSessionConfig)
    quest: QuestSessionConfig = field(default_factory=QuestSessionConfig)


@dataclass(slots=True, frozen=True)
class PlaybackDriverConfig:
    timing: PlaybackTimingConfig = field(default_factory=PlaybackTimingConfig)
    world: PlaybackWorldConfig = field(default_factory=PlaybackWorldConfig)
    events: PlaybackEventConfig = field(default_factory=PlaybackEventConfig)
    session_defaults: PlaybackSessionDefaults = field(default_factory=PlaybackSessionDefaults)
    sessions: PlaybackSessionConfigs = field(default_factory=PlaybackSessionConfigs)


@dataclass(slots=True)
class PlaybackTickOutcome:
    tick_index: int
    dt_tick: float
    dt_tick_ms_i32: int | None
    tick_events: list[object]
    pre_step_events: list[object]
    post_step_events: list[object]
    world: WorldState
    step: DeterministicStepResult
    step_events: WorldEvents
    command_hash: str
    elapsed_ms: float
    dt_sim: float
    rng_marks: dict[str, int]
    creature_count_world_step: int
    rng_before_events: int
    rng_after_events: int
    rng_before_post_events: int | None
    rng_after_post_events: int | None
    tick_rng_rows: list[RngTraceDraw]
    spawn_timeline_ms: float | None = None
    completion_transition_ms: float | None = None
    play_hit_sfx: bool = False
    play_completion_music: bool = False


@dataclass(slots=True)
class PlaybackTerminalOutcome:
    tick_index: int
    dt_tick: float
    terminal_events: list[object]
    world: WorldState
    rng_before_events: int
    rng_after_events: int


@dataclass(slots=True)
class SurvivalPlaybackRuntime:
    session: SurvivalDeterministicSession
    partition_events: bool

    def strict_events(self, *, default_strict_events: bool) -> bool:
        return bool(default_strict_events)

    def partition_tick_events(
        self,
        tick_events: list[object],
        *,
        defer_menu_open: bool,
    ) -> tuple[list[object], list[object]]:
        if not bool(self.partition_events):
            return list(tick_events), []
        return partition_tick_events(tick_events, defer_menu_open=bool(defer_menu_open))

    def enrich_tick_outcome(self, outcome: PlaybackTickOutcome, *, tick: DeterministicSessionStepTick) -> None:
        _ = outcome, tick

    def checkpoint_elapsed_ms(self, outcome: PlaybackTickOutcome) -> float:
        return float(outcome.elapsed_ms)

    def terminal_checkpoint_rng_marks(self, terminal: PlaybackTerminalOutcome) -> dict[str, int]:
        _ = terminal
        return {}

    def terminal_checkpoint_elapsed_ms(self) -> float:
        return float(self.session.elapsed_ms)

    def run_result_elapsed_ms(self) -> int:
        return int(self.session.elapsed_ms)


@dataclass(slots=True)
class RushPlaybackRuntime:
    session: RushDeterministicSession
    strict_events_override: bool | None

    def strict_events(self, *, default_strict_events: bool) -> bool:
        if self.strict_events_override is None:
            return bool(default_strict_events)
        return bool(self.strict_events_override)

    def partition_tick_events(
        self,
        tick_events: list[object],
        *,
        defer_menu_open: bool,
    ) -> tuple[list[object], list[object]]:
        _ = defer_menu_open
        return list(tick_events), []

    def enrich_tick_outcome(self, outcome: PlaybackTickOutcome, *, tick: DeterministicSessionStepTick) -> None:
        _ = outcome, tick

    def checkpoint_elapsed_ms(self, outcome: PlaybackTickOutcome) -> float:
        return float(outcome.elapsed_ms)

    def terminal_checkpoint_rng_marks(self, terminal: PlaybackTerminalOutcome) -> dict[str, int]:
        return {
            "before_events": int(terminal.rng_before_events),
            "after_events": int(terminal.rng_after_events),
        }

    def terminal_checkpoint_elapsed_ms(self) -> float:
        return float(self.session.elapsed_ms)

    def run_result_elapsed_ms(self) -> int:
        return int(self.session.elapsed_ms)


@dataclass(slots=True)
class QuestPlaybackRuntime:
    session: QuestDeterministicSession
    partition_events: bool
    result_uses_spawn_timeline_ms: bool

    def strict_events(self, *, default_strict_events: bool) -> bool:
        return bool(default_strict_events)

    def partition_tick_events(
        self,
        tick_events: list[object],
        *,
        defer_menu_open: bool,
    ) -> tuple[list[object], list[object]]:
        if not bool(self.partition_events):
            return list(tick_events), []
        return partition_tick_events(tick_events, defer_menu_open=bool(defer_menu_open))

    def enrich_tick_outcome(self, outcome: PlaybackTickOutcome, *, tick: DeterministicSessionStepTick) -> None:
        if not isinstance(tick, QuestDeterministicSessionTick):
            raise ReplayRunnerError("quest playback session returned non-quest tick payload")
        outcome.spawn_timeline_ms = float(tick.spawn_timeline_ms)
        outcome.completion_transition_ms = float(tick.completion_transition_ms)
        outcome.play_hit_sfx = bool(tick.play_hit_sfx)
        outcome.play_completion_music = bool(tick.play_completion_music)

    def checkpoint_elapsed_ms(self, outcome: PlaybackTickOutcome) -> float:
        if outcome.spawn_timeline_ms is not None:
            return float(outcome.spawn_timeline_ms)
        return float(outcome.elapsed_ms)

    def terminal_checkpoint_rng_marks(self, terminal: PlaybackTerminalOutcome) -> dict[str, int]:
        _ = terminal
        return {}

    def terminal_checkpoint_elapsed_ms(self) -> float:
        return float(self.session.spawn_timeline_ms)

    def run_result_elapsed_ms(self) -> int:
        if bool(self.result_uses_spawn_timeline_ms):
            return int(self.session.spawn_timeline_ms)
        return int(self.session.elapsed_ms)


PlaybackModeRuntime: TypeAlias = SurvivalPlaybackRuntime | RushPlaybackRuntime | QuestPlaybackRuntime


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

        self.mode_id = int(replay.header.game_mode_id)
        if self.mode_id not in (int(GameMode.SURVIVAL), int(GameMode.RUSH), int(GameMode.QUESTS)):
            raise ReplayRunnerError(f"unsupported replay game_mode_id={self.mode_id}")

        tick_rate = int(replay.header.tick_rate)
        if tick_rate <= 0:
            raise ReplayRunnerError(f"invalid tick_rate: {tick_rate}")
        self.tick_rate = int(tick_rate)
        self.dt_frame = 1.0 / float(self.tick_rate)

        self.world_size = self._resolve_world_size()
        self.world = self._prepare_world()
        self.events_by_tick = self._build_events_by_tick()
        self.fx_queue, self.fx_queue_rotated = self._resolve_fx_queues()

        apply_world_dt_steps = should_apply_world_dt_steps_for_replay(
            original_capture_replay=False,
            dt_frame_overrides=self.config.timing.dt_frame_overrides,
            dt_frame_ms_i32_overrides=self.config.timing.dt_frame_ms_i32_overrides,
        )
        self._mode_runtime = self._build_mode_runtime(apply_world_dt_steps=bool(apply_world_dt_steps))
        self.session: DeterministicSession = self._mode_runtime.session

        inputs = replay.inputs
        self.tick_limit = (
            len(inputs)
            if self.options.max_ticks is None
            else min(len(inputs), max(0, int(self.options.max_ticks)))
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
            preserve_bugs=bool(self.replay.header.preserve_bugs),
        )
        reset_players(
            world.players,
            world_size=float(self.world_size),
            player_count=int(self.replay.header.player_count),
        )
        world.state.status = status_from_snapshot(
            quest_unlock_index=int(self.replay.header.status.quest_unlock_index),
            quest_unlock_index_full=int(self.replay.header.status.quest_unlock_index_full),
            weapon_usage_counts=self.replay.header.status.weapon_usage_counts,
        )

        if self.mode_id in (int(GameMode.SURVIVAL), int(GameMode.RUSH)):
            apply_replay_bootstrap(
                self.replay.header,
                rng=world.state.rng,
                world_size=float(self.world_size),
                strict=True,
            )
        else:
            world.state.rng.srand(int(self.replay.header.seed))

        return world

    def _build_events_by_tick(self) -> dict[int, list[object]]:
        events_by_tick: dict[int, list[object]] = {}
        for event in self.replay.events:
            events_by_tick.setdefault(int(event.tick_index), []).append(event)
        return events_by_tick

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
            quest_level = resolve_quest_level_from_replay(self.replay)
            quest = quest_by_level(quest_level) if quest_level else None
            if quest is None:
                raise ReplayRunnerError(f"unsupported quest replay: unknown quest_level={quest_level!r}")

            if quest_stage_major is None or quest_stage_minor is None:
                quest_stage_major, quest_stage_minor = quest.level_key
            if start_weapon_id is None:
                start_weapon_id = quest.start_weapon_id

            ctx = QuestContext(
                width=int(self.world_size),
                height=int(self.world_size),
                player_count=int(self.replay.header.player_count),
            )
            spawn_entries = tuple(
                build_quest_spawn_table(
                    quest,
                    ctx,
                    seed=int(self.replay.header.seed),
                    hardcore=bool(self.replay.header.hardcore),
                    full_version=True,
                ),
            )
        else:
            spawn_entries = tuple(spawn_entries)

        return spawn_entries, quest_stage_major, quest_stage_minor, start_weapon_id

    def _build_mode_runtime(self, *, apply_world_dt_steps: bool) -> PlaybackModeRuntime:
        damage_scale_by_type = build_damage_scale_by_type()
        defaults = self.config.session_defaults
        sessions = self.config.sessions
        mode_id = int(self.mode_id)

        if mode_id == int(GameMode.SURVIVAL):
            session = SurvivalDeterministicSession(
                world=self.world,
                world_size=float(self.world_size),
                damage_scale_by_type=damage_scale_by_type,
                fx_queue=self.fx_queue,
                fx_queue_rotated=self.fx_queue_rotated,
                detail_preset=int(self.replay.header.detail_preset),
                fx_toggle=int(self.replay.header.fx_toggle),
                game_tune_started=bool(defaults.game_tune_started),
                apply_world_dt_steps=bool(apply_world_dt_steps),
                clear_fx_queues_each_tick=bool(defaults.clear_fx_queues_each_tick),
            )
            return SurvivalPlaybackRuntime(
                session=session,
                partition_events=bool(sessions.survival.partition_events),
            )

        if mode_id == int(GameMode.RUSH):
            rush_config = sessions.rush
            if bool(rush_config.enforce_loadout):
                enforce_rush_loadout(self.world)
            session = RushDeterministicSession(
                world=self.world,
                world_size=float(self.world_size),
                damage_scale_by_type=damage_scale_by_type,
                fx_queue=self.fx_queue,
                fx_queue_rotated=self.fx_queue_rotated,
                detail_preset=int(self.replay.header.detail_preset),
                fx_toggle=int(self.replay.header.fx_toggle),
                game_tune_started=bool(defaults.game_tune_started),
                clear_fx_queues_each_tick=bool(defaults.clear_fx_queues_each_tick),
                enforce_loadout=(lambda: enforce_rush_loadout(self.world))
                if bool(rush_config.enforce_loadout)
                else None,
                use_dt_frame_ms_i32=bool(rush_config.use_dt_frame_ms_i32),
            )
            return RushPlaybackRuntime(
                session=session,
                strict_events_override=rush_config.strict_events_override,
            )

        quest_config = sessions.quest
        spawn_entries, quest_stage_major, quest_stage_minor, start_weapon_id = self._resolve_quest_setup(
            quest_config,
        )

        if quest_stage_major is not None:
            self.world.state.quest_stage_major = int(quest_stage_major)
        if quest_stage_minor is not None:
            self.world.state.quest_stage_minor = int(quest_stage_minor)

        weapon_id = start_weapon_id or WeaponId.PISTOL
        if weapon_id <= WeaponId.NONE:
            weapon_id = WeaponId.PISTOL
        for player in self.world.players:
            weapon_assign_player(player, weapon_id)

        if bool(quest_config.disable_capture_spawn_events_authoritative):
            self.world.creatures.capture_spawn_events_authoritative = False

        session = QuestDeterministicSession(
            world=self.world,
            world_size=float(self.world_size),
            damage_scale_by_type=damage_scale_by_type,
            fx_queue=self.fx_queue,
            fx_queue_rotated=self.fx_queue_rotated,
            spawn_entries=tuple(spawn_entries),
            detail_preset=int(self.replay.header.detail_preset),
            fx_toggle=int(self.replay.header.fx_toggle),
            game_tune_started=bool(defaults.game_tune_started),
            apply_world_dt_steps=bool(apply_world_dt_steps),
            clear_fx_queues_each_tick=bool(defaults.clear_fx_queues_each_tick),
            finalize_post_render_lifecycle_each_tick=bool(quest_config.finalize_post_render_lifecycle_each_tick),
        )
        return QuestPlaybackRuntime(
            session=session,
            partition_events=bool(quest_config.partition_events),
            result_uses_spawn_timeline_ms=bool(quest_config.result_uses_spawn_timeline_ms),
        )

    def run_tick(self, tick_index: int, *, defer_menu_open: bool | None = None) -> PlaybackTickOutcome:
        if tick_index < 0 or tick_index >= int(self.tick_limit):
            raise ReplayRunnerError(f"tick_index out of range: {tick_index} (tick_limit={self.tick_limit})")

        state = self.world.state
        state.game_mode = int(self.mode_id)
        state.demo_mode_active = False

        timing = self.config.timing
        if timing.inter_tick_rand_draws_by_tick is not None:
            draws = timing.inter_tick_rand_draws_by_tick.get(int(tick_index))
            if draws is None:
                draws = int(timing.inter_tick_rand_draws)
            for _ in range(max(0, int(draws))):
                state.rng.rand()

        dt_tick = resolve_dt_frame(
            tick_index=int(tick_index),
            default_dt_frame=float(self.dt_frame),
            dt_frame_overrides=timing.dt_frame_overrides,
        )
        dt_tick_ms_i32 = resolve_dt_frame_ms_i32(
            tick_index=int(tick_index),
            dt_frame=float(dt_tick),
            dt_frame_ms_i32_overrides=timing.dt_frame_ms_i32_overrides,
        )

        tick_events = self.events_by_tick.get(int(tick_index), [])
        defer_menu_open_value = (
            bool(defer_menu_open)
            if defer_menu_open is not None
            else bool(self.config.events.defer_menu_open)
        )
        pre_step_events, post_step_events = self._mode_runtime.partition_tick_events(
            tick_events,
            defer_menu_open=bool(defer_menu_open_value),
        )

        strict_events = self._mode_runtime.strict_events(
            default_strict_events=bool(self.config.events.strict_events),
        )
        rng_before_events = int(state.rng.state)
        with _tick_rng_trace(state.rng, enabled=bool(self.options.trace_rng)) as tick_rng_rows:
            apply_replay_tick_events(
                pre_step_events,
                tick_index=int(tick_index),
                dt_frame=float(dt_tick),
                world=self.world,
                game_mode_id=int(self.mode_id),
                strict_events=bool(strict_events),
            )
            rng_after_events = int(state.rng.state)

            player_inputs = unpack_tick_inputs(self.replay.inputs[int(tick_index)])
            tick = self.session.step_tick(
                dt_frame=float(dt_tick),
                dt_frame_ms_i32=(int(dt_tick_ms_i32) if dt_tick_ms_i32 is not None else None),
                inputs=player_inputs,
                trace_rng=bool(self.options.trace_rng),
            )

            step = tick.step
            events = step.events
            rng_before_post_events = int(state.rng.state)
            if post_step_events:
                apply_replay_tick_events(
                    post_step_events,
                    tick_index=int(tick_index),
                    dt_frame=float(dt_tick),
                    world=self.world,
                    game_mode_id=int(self.mode_id),
                    strict_events=bool(strict_events),
                )
            rng_after_post_events = int(state.rng.state)

        if timing.inter_tick_rand_draws_by_tick is None:
            draws = max(0, int(timing.inter_tick_rand_draws))
            for _ in range(draws):
                state.rng.rand()

        outcome = PlaybackTickOutcome(
            tick_index=int(tick_index),
            dt_tick=float(dt_tick),
            dt_tick_ms_i32=(int(dt_tick_ms_i32) if dt_tick_ms_i32 is not None else None),
            tick_events=list(tick_events),
            pre_step_events=list(pre_step_events),
            post_step_events=list(post_step_events),
            world=self.world,
            step=step,
            step_events=events,
            command_hash=str(step.command_hash),
            elapsed_ms=float(tick.elapsed_ms),
            dt_sim=float(step.dt_sim),
            rng_marks=dict(tick.rng_marks),
            creature_count_world_step=int(tick.creature_count_world_step),
            rng_before_events=int(rng_before_events),
            rng_after_events=int(rng_after_events),
            rng_before_post_events=(int(rng_before_post_events) if post_step_events else None),
            rng_after_post_events=(int(rng_after_post_events) if post_step_events else None),
            tick_rng_rows=list(tick_rng_rows),
        )
        self._mode_runtime.enrich_tick_outcome(outcome, tick=tick)
        return outcome

    def apply_terminal_events(self, tick_index: int) -> PlaybackTerminalOutcome | None:
        events_config = self.config.events
        if not bool(events_config.apply_terminal_tick_events):
            return None
        if int(tick_index) != int(len(self.replay.inputs)):
            return None

        if bool(events_config.terminal_events_use_resolved_dt):
            dt_tick = resolve_dt_frame(
                tick_index=int(tick_index),
                default_dt_frame=float(self.dt_frame),
                dt_frame_overrides=self.config.timing.dt_frame_overrides,
            )
        else:
            dt_tick = float(self.dt_frame)

        terminal_events = self.events_by_tick.get(int(tick_index), [])
        strict_events = self._mode_runtime.strict_events(
            default_strict_events=bool(events_config.strict_events),
        )

        rng_before_events = int(self.world.state.rng.state)
        apply_replay_tick_events(
            terminal_events,
            tick_index=int(tick_index),
            dt_frame=float(dt_tick),
            world=self.world,
            game_mode_id=int(self.mode_id),
            strict_events=bool(strict_events),
        )
        rng_after_events = int(self.world.state.rng.state)

        return PlaybackTerminalOutcome(
            tick_index=int(tick_index),
            dt_tick=float(dt_tick),
            terminal_events=list(terminal_events),
            world=self.world,
            rng_before_events=int(rng_before_events),
            rng_after_events=int(rng_after_events),
        )

    def _append_checkpoint_for_tick(
        self,
        *,
        outcome: PlaybackTickOutcome,
        checkpoints_out: list[ReplayCheckpoint],
        checkpoint_use_world_step_creature_count: bool,
    ) -> None:
        checkpoint_rng_marks = dict(outcome.rng_marks)
        checkpoint_rng_marks["before_events"] = int(outcome.rng_before_events)
        after_events_rng = int(outcome.rng_after_events)
        if outcome.post_step_events and outcome.rng_after_post_events is not None:
            after_events_rng = int(outcome.rng_after_post_events)
        checkpoint_rng_marks["after_events"] = int(after_events_rng)
        if outcome.post_step_events and outcome.rng_before_post_events is not None and outcome.rng_after_post_events is not None:
            checkpoint_rng_marks["before_post_events"] = int(outcome.rng_before_post_events)
            checkpoint_rng_marks["after_post_events"] = int(outcome.rng_after_post_events)

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
                deaths=outcome.step_events.deaths,
                events=outcome.step_events,
                command_hash=str(outcome.command_hash),
            ),
        )

    def _append_terminal_checkpoint(
        self,
        *,
        terminal: PlaybackTerminalOutcome,
        checkpoints_out: list[ReplayCheckpoint],
    ) -> None:
        checkpoints_out.append(
            build_checkpoint(
                tick_index=int(terminal.tick_index),
                world=self.world,
                elapsed_ms=float(self._mode_runtime.terminal_checkpoint_elapsed_ms()),
                rng_marks=self._mode_runtime.terminal_checkpoint_rng_marks(terminal),
                deaths=[],
                events=WorldEvents(hits=[], deaths=(), pickups=[], sfx=[]),
                command_hash="",
            ),
        )

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
        terminal_observer: Callable[[PlaybackTerminalOutcome], None] | None = None,
        defer_menu_open: bool | None = None,
    ) -> RunResult:
        for tick_index in range(int(self.tick_limit)):
            outcome = self.run_tick(
                int(tick_index),
                defer_menu_open=defer_menu_open,
            )

            if tick_begin_observer is not None:
                tick_begin_observer(
                    int(outcome.tick_index),
                    outcome.world,
                    float(outcome.dt_tick),
                    list(outcome.tick_events),
                    list(outcome.pre_step_events),
                    list(outcome.post_step_events),
                )

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
                    outcome.step_events,
                    dict(outcome.rng_marks),
                )

            if tick_observer is not None:
                tick_observer(int(outcome.tick_index), self.world)

            if tick_end_observer is not None:
                tick_end_observer(outcome)

            if tick_progress_callback is not None:
                tick_progress_callback(int(outcome.tick_index) + 1)

        terminal = self.apply_terminal_events(int(self.tick_limit))
        if terminal is not None:
            if checkpoints_out is not None and checkpoint_ticks is not None and int(terminal.tick_index) in checkpoint_ticks:
                self._append_terminal_checkpoint(
                    terminal=terminal,
                    checkpoints_out=checkpoints_out,
                )
            if terminal_observer is not None:
                terminal_observer(terminal)

        return self.build_run_result(ticks=int(self.tick_limit))

    def build_run_result(self, *, ticks: int) -> RunResult:
        shots_fired, shots_hit = player0_shots(self.world.state)
        most_used_weapon_id = player0_most_used_weapon_id(self.world.state, self.world.players)
        score_xp = int(self.world.players[0].experience) if self.world.players else 0

        return RunResult(
            game_mode_id=int(self.mode_id),
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
    def survival_session(self) -> SurvivalDeterministicSession | None:
        return self.session if isinstance(self.session, SurvivalDeterministicSession) else None

    @property
    def rush_session(self) -> RushDeterministicSession | None:
        return self.session if isinstance(self.session, RushDeterministicSession) else None

    @property
    def quest_session(self) -> QuestDeterministicSession | None:
        return self.session if isinstance(self.session, QuestDeterministicSession) else None
