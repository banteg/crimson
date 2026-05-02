from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TypeAlias

from crimson.quests.level import QuestLevel
from grim.rand import CallerStatic, CrtRand, RecordedCallerStatic, RngTraceSink

from ...game_modes import GameMode
from ...persistence.save_status import GameStatus
from ...quests import quest_by_level
from ...quests.runtime import build_quest_spawn_table
from ...quests.types import QuestContext, QuestDefinition, SpawnEntry
from ...replay import Replay, warn_on_game_version_mismatch
from ...replay.checkpoints import ReplayCheckpoint
from ...replay.checkpoints import build_checkpoint as build_replay_checkpoint
from ...replay.header_settings import session_settings_from_replay_header
from ...replay.input_codec import unpack_tick_inputs
from ...rng_caller_static import RngCallerStatic
from ...sim.bootstrap import TerrainSetup, advance_explicit_terrain, advance_unlock_terrain
from ...sim.hooks import TickResult
from ...sim.input_providers import ResolvedTick
from ...sim.session_builders import (
    build_quest_session,
    build_rush_session,
    build_survival_session,
    build_tutorial_session,
    build_typo_session,
    enforce_rush_loadout,
)
from ...sim.sessions import (
    DeterministicSession,
    QuestSpawnState,
)
from ...sim.world_state import WorldState
from ...typo.state import typo_shot_counts
from ...weapons import WeaponId
from ...world.sim_world_state import reset_world_players
from .replay_timing import should_apply_world_dt_steps_for_replay
from .setup import (
    ReplayRunnerError,
    RunResult,
    build_damage_scale_by_type,
    player0_most_used_weapon_id,
    player0_shots,
)

RngTraceDraw: TypeAlias = tuple[int, int, int, RecordedCallerStatic]
TickRngTraceObserver: TypeAlias = Callable[[TickResult, tuple[RngTraceDraw, ...]], None]
TickProgressCallback: TypeAlias = Callable[[int], None]
TickBeginObserver: TypeAlias = Callable[
    [int, WorldState, float],
    None,
]
TickEndObserver: TypeAlias = Callable[[TickResult, WorldState], None]


def require_quest_level_from_replay(replay: Replay) -> QuestLevel:
    if replay.header.quest_level is None:
        raise ReplayRunnerError("quest replays require a valid header.quest_level")
    return replay.header.quest_level


def resolve_replay_quest_definition(
    replay: Replay,
    *,
    quest_level: QuestLevel | None = None,
) -> QuestDefinition:
    level = quest_level if quest_level is not None else require_quest_level_from_replay(replay)
    quest = quest_by_level(level)
    if quest is None:
        raise ReplayRunnerError(f"unsupported quest replay: unknown quest_level={level.text!r}")
    return quest

@contextmanager
def _tick_rng_trace(rng: object, *, enabled: bool, strict: bool = False) -> Iterator[list[RngTraceDraw]]:
    draws: list[RngTraceDraw] = []
    if not enabled or not isinstance(rng, CrtRand):
        yield draws
        return

    previous_sink = rng.trace_sink
    previous_require_caller = rng.trace_require_caller

    def _sink(
        state_before_u32: int,
        state_after_u32: int,
        value_15: int,
        caller: CallerStatic | None,
    ) -> None:
        draws.append(
            (
                int(state_before_u32),
                int(value_15),
                int(state_after_u32),
                caller,
            ),
        )

    trace_sink: RngTraceSink = _sink
    rng.set_trace_sink(trace_sink, require_caller=bool(strict))
    try:
        yield draws
    finally:
        rng.set_trace_sink(previous_sink, require_caller=bool(previous_require_caller))


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


class PlaybackDriver:
    """Canonical replay driver."""

    def __init__(
        self,
        replay: Replay,
        *,
        max_ticks: int | None = None,
        trace_rng: bool = False,
        strict_rng_trace: bool = False,
        version_mismatch_action: str | None = "verification",
        world_size: float | None = None,
        inter_tick_rand_draws: int = 0,
        inter_tick_rand_draws_by_tick: dict[int, int] | None = None,
        spawn_entries: tuple[SpawnEntry, ...] | None = None,
        start_weapon_id: WeaponId | None = None,
    ) -> None:
        self.replay = replay
        self.max_ticks = max_ticks
        self.trace_rng = bool(trace_rng)
        self.strict_rng_trace = bool(strict_rng_trace)
        self.inter_tick_rand_draws = max(0, int(inter_tick_rand_draws))
        self.inter_tick_rand_draws_by_tick = inter_tick_rand_draws_by_tick
        self._provided_world_size = float(world_size) if world_size is not None else None
        self._quest_spawn_entries = tuple(spawn_entries) if spawn_entries is not None else None
        self._quest_start_weapon_id = start_weapon_id
        self._quest_spawn_state: QuestSpawnState | None = None
        self._quest_definition: QuestDefinition | None = None
        self._quest_total_spawn_count = 0
        self._terrain_setup: TerrainSetup | None = None
        self._quest_spawn_entries_resolved: tuple[SpawnEntry, ...] = ()
        self._quest_start_weapon_resolved: WeaponId | None = None

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
        world.state.rng.srand(int(self.replay.header.seed))
        reset_world_players(
            world.players,
            state=world.state,
            world_size=float(self.world_size),
            player_count=int(self.session_settings.player_count),
        )
        world.state.status = GameStatus.from_data(
            path=Path("replay://status"),
            data=self.replay.header.status,
            dirty=False,
        )
        self._quest_definition = None
        self._quest_total_spawn_count = 0
        self._terrain_setup = None
        self._quest_spawn_entries_resolved = ()
        self._quest_start_weapon_resolved = None

        match self.mode_id:
            case GameMode.SURVIVAL | GameMode.RUSH:
                terrain = advance_unlock_terrain(
                    world.state.rng,
                    unlock_index=int(self.replay.header.status.quest_unlock_index),
                    width=int(self.world_size),
                    height=int(self.world_size),
                )
                self._terrain_setup = terrain
            case GameMode.TYPO:
                terrain = advance_unlock_terrain(
                    world.state.rng,
                    unlock_index=int(self.replay.header.status.quest_unlock_index),
                    width=int(self.world_size),
                    height=int(self.world_size),
                )
                self._terrain_setup = terrain
            case GameMode.TUTORIAL:
                terrain = advance_unlock_terrain(
                    world.state.rng,
                    unlock_index=int(self.replay.header.status.quest_unlock_index),
                    width=int(self.world_size),
                    height=int(self.world_size),
                )
                self._terrain_setup = terrain
            case GameMode.QUESTS:
                quest_definition = resolve_replay_quest_definition(self.replay)
                quest_level = quest_definition.level
                start_weapon_id = (
                    quest_definition.start_weapon_id
                    if self._quest_start_weapon_id is None
                    else self._quest_start_weapon_id
                )
                ctx = QuestContext(
                    width=int(self.world_size),
                    height=int(self.world_size),
                    player_count=int(self.session_settings.player_count),
                )
                advance_unlock_terrain(
                    world.state.rng,
                    unlock_index=int(self.replay.header.status.quest_unlock_index),
                    width=int(self.world_size),
                    height=int(self.world_size),
                )
                # Native `quest_start_selected()` burns one `crt_rand()` for
                # `highscore_record_random_tag` before quest terrain and spawn setup.
                world.state.rng.rand_tagged(RngCallerStatic.QUEST_START_SELECTED_HIGHSCORE_RANDOM_TAG)
                quest_terrain = advance_explicit_terrain(
                    world.state.rng,
                    terrain_slots=quest_definition.terrain_slots,
                    width=int(self.world_size),
                    height=int(self.world_size),
                )
                generated_spawn_entries = tuple(
                    build_quest_spawn_table(
                        quest_definition,
                        ctx,
                        rng=world.state.rng,
                        hardcore=bool(self.replay.header.hardcore),
                        full_version=True,
                    ),
                )
                spawn_entries = (
                    tuple(self._quest_spawn_entries)
                    if self._quest_spawn_entries is not None
                    else generated_spawn_entries
                )
                world.state.quest_level = quest_level
                self._quest_definition = quest_definition
                self._quest_total_spawn_count = int(sum(int(entry.count) for entry in spawn_entries))
                self._quest_spawn_entries_resolved = spawn_entries
                self._quest_start_weapon_resolved = start_weapon_id
                self._terrain_setup = TerrainSetup(
                    terrain_slots=quest_definition.terrain_slots,
                    terrain_seed=quest_terrain.terrain_seed,
                )
            case _:
                pass

        return world

    def _build_session(self, *, apply_world_dt_steps: bool) -> DeterministicSession:
        damage_scale_by_type = build_damage_scale_by_type()
        self._quest_spawn_state = None
        match self.mode_id:
            case GameMode.SURVIVAL:
                session, _ = build_survival_session(
                    world=self.world,
                    world_size=self.world_size,
                    damage_scale_by_type=damage_scale_by_type,
                    detail_preset=self.replay.header.detail_preset,
                    violence_disabled=self.replay.header.violence_disabled,
                    game_tune_started=False,
                    apply_world_dt_steps=apply_world_dt_steps,
                    finalize_post_render_lifecycle=True,
                )
                return session
            case GameMode.RUSH:
                enforce_rush_loadout(self.world)
                session, _ = build_rush_session(
                    world=self.world,
                    world_size=self.world_size,
                    damage_scale_by_type=damage_scale_by_type,
                    detail_preset=self.replay.header.detail_preset,
                    violence_disabled=self.replay.header.violence_disabled,
                    game_tune_started=False,
                    finalize_post_render_lifecycle=True,
                )
                return session
            case GameMode.QUESTS:
                quest_definition = self._quest_definition
                if quest_definition is None:
                    raise ReplayRunnerError("quest replay startup must resolve quest definition before session build")
                spawn_entries = tuple(self._quest_spawn_entries_resolved)
                quest_level = quest_definition.level
                start_weapon_id = self._quest_start_weapon_resolved
                session, quest_state = build_quest_session(
                    world=self.world,
                    world_size=self.world_size,
                    damage_scale_by_type=damage_scale_by_type,
                    detail_preset=self.replay.header.detail_preset,
                    violence_disabled=self.replay.header.violence_disabled,
                    game_tune_started=False,
                    demo_mode_active=self.world.state.demo_mode_active,
                    apply_world_dt_steps=apply_world_dt_steps,
                    finalize_post_render_lifecycle=True,
                    spawn_entries=spawn_entries,
                    quest_level=quest_level,
                    start_weapon_id=start_weapon_id,
                )
                self._quest_spawn_state = quest_state
                return session
            case GameMode.TYPO:
                return build_typo_session(
                    world=self.world,
                    world_size=self.world_size,
                    damage_scale_by_type=damage_scale_by_type,
                    detail_preset=self.replay.header.detail_preset,
                    violence_disabled=self.replay.header.violence_disabled,
                    game_tune_started=False,
                    dictionary_words=self.replay.header.typo_dictionary_words,
                    highscore_names=self.replay.header.typo_highscore_names,
                )
            case GameMode.TUTORIAL:
                return build_tutorial_session(
                    world=self.world,
                    world_size=self.world_size,
                    damage_scale_by_type=damage_scale_by_type,
                    detail_preset=self.replay.header.detail_preset,
                    violence_disabled=self.replay.header.violence_disabled,
                    game_tune_started=False,
                    demo_mode_active=False,
                )
            case _:
                raise ReplayRunnerError(f"unsupported replay game_mode_id={int(self.mode_id)}")

    def _prepare_tick(self, *, tick_index: int) -> None:
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
                state.rng.rand_tagged(RngCallerStatic.REPLAY_DRIVER_INTER_TICK_DRAW_BY_TICK)

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
            deaths=tick_result.payload.step.events.deaths,
            events=tick_result.payload.step.events,
        )

    def step_tick(self, tick_index: int) -> TickResult:
        tick_index = int(tick_index)
        self._prepare_tick(tick_index=tick_index)
        self._last_tick_rng_rows = ()
        replay_tick = self.replay.ticks[tick_index]
        dt_tick = float(replay_tick.dt)
        inputs = unpack_tick_inputs(replay_tick.inputs)
        commands = list(replay_tick.commands)
        with _tick_rng_trace(
            self.world.state.rng,
            enabled=bool(self.trace_rng),
            strict=bool(self.strict_rng_trace),
        ) as tick_rng_rows:
            source_tick = ResolvedTick(
                tick_index=int(tick_index),
                dt_seconds=float(dt_tick),
                inputs=tuple(inputs),
                commands=tuple(commands),
            )

            session_tick = self.session.step_tick(
                dt=dt_tick,
                inputs=inputs,
                trace_rng=self.trace_rng,
                commands=commands,
            )
            tick_result = TickResult(
                source_tick=source_tick,
                payload=session_tick,
                replay_tick_index=int(tick_index),
            )

        if self.inter_tick_rand_draws_by_tick is None:
            draws = max(0, int(self.inter_tick_rand_draws))
            for _ in range(draws):
                self.world.state.rng.rand_tagged(RngCallerStatic.REPLAY_DRIVER_INTER_TICK_DRAW)
        self._last_tick_rng_rows = tuple(tick_rng_rows)
        return tick_result

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
        if self.mode_id == GameMode.TYPO:
            shots_fired, shots_hit = typo_shot_counts(self.world.state.typo)
        else:
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

    @property
    def quest_definition(self) -> QuestDefinition | None:
        return self._quest_definition

    @property
    def quest_total_spawn_count(self) -> int:
        return int(self._quest_total_spawn_count)

    @property
    def terrain_setup(self) -> TerrainSetup | None:
        return self._terrain_setup


def build_verify_playback_driver(
    replay: Replay,
    *,
    max_ticks: int | None = None,
    warn_on_version_mismatch: bool = True,
    trace_rng: bool = False,
    strict_rng_trace: bool = False,
    inter_tick_rand_draws: int = 0,
    inter_tick_rand_draws_by_tick: dict[int, int] | None = None,
    spawn_entries: tuple[SpawnEntry, ...] | None = None,
    start_weapon_id: WeaponId | None = None,
) -> PlaybackDriver:
    """Build the canonical headless/verification replay driver."""

    return PlaybackDriver(
        replay,
        max_ticks=max_ticks,
        trace_rng=bool(trace_rng),
        strict_rng_trace=bool(strict_rng_trace),
        version_mismatch_action=("verification" if bool(warn_on_version_mismatch) else None),
        inter_tick_rand_draws=int(inter_tick_rand_draws),
        inter_tick_rand_draws_by_tick=inter_tick_rand_draws_by_tick,
        spawn_entries=spawn_entries,
        start_weapon_id=start_weapon_id,
    )


def build_runtime_playback_driver(
    replay: Replay,
    *,
    max_ticks: int | None,
    trace_rng: bool,
    world_size: float,
    spawn_entries: tuple[SpawnEntry, ...] | None = None,
    start_weapon_id: WeaponId | None = None,
) -> PlaybackDriver:
    """Build the canonical live replay-playback driver."""

    return PlaybackDriver(
        replay,
        max_ticks=max_ticks,
        trace_rng=bool(trace_rng),
        version_mismatch_action=None,
        world_size=float(world_size),
        spawn_entries=spawn_entries,
        start_weapon_id=start_weapon_id,
    )
