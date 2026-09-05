from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import msgspec

from crimson.quests.level import QuestLevel
from grim.rand import CallerStatic, CrtRand, RecordedCallerStatic, RngTraceSink

from ...game_modes import GameMode
from ...quests import quest_by_level
from ...quests.types import QuestDefinition, SpawnEntry
from ...replay import Replay, warn_on_game_version_mismatch
from ...replay.checkpoints import ReplayCheckpoint
from ...replay.checkpoints import build_checkpoint as build_replay_checkpoint
from ...replay.input_codec import unpack_tick_inputs
from ...sim.bootstrap import TerrainSetup
from ...sim.hooks import TickResult
from ...sim.input_providers import GameCommand, ResolvedTick
from ...sim.run_init import initialize_run
from ...sim.run_spec import RunSpec
from ...sim.sessions import (
    QuestSessionRuntime,
    QuestSpawnState,
)
from ...sim.world_state import WorldState
from ...typo.state import typo_shot_counts
from ...weapons import WeaponId
from .replay_timing import should_apply_world_dt_steps_for_replay
from .setup import (
    ReplayRunnerError,
    RunResult,
    player0_most_used_weapon_id,
    player0_shots,
)

type RngTraceDraw = tuple[int, int, int, RecordedCallerStatic]


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


class PlaybackWalkObserver(msgspec.Struct):
    def before_tick(self, tick_index: int, world: WorldState, dt_tick: float) -> None:
        _ = tick_index, world, dt_tick

    def after_tick(self, tick_result: TickResult, world: WorldState) -> None:
        _ = tick_result, world

    def rng_trace(self, tick_result: TickResult, draws: tuple[RngTraceDraw, ...]) -> None:
        _ = tick_result, draws

    def progress(self, next_tick_index: int) -> None:
        _ = next_tick_index


class PlaybackWalkResult(msgspec.Struct, frozen=True):
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
        spawn_entries: tuple[SpawnEntry, ...] | None = None,
        start_weapon_id: WeaponId | None = None,
    ) -> None:
        self.replay = replay
        self.max_ticks = max_ticks
        self.trace_rng = bool(trace_rng)
        self.strict_rng_trace = bool(strict_rng_trace)

        if version_mismatch_action is not None:
            warn_on_game_version_mismatch(replay, action=str(version_mismatch_action))

        mode_raw = int(self.replay.header.game_mode_id)
        try:
            self.mode_id = GameMode(mode_raw)
        except ValueError as exc:
            raise ReplayRunnerError(f"unsupported replay game_mode_id={mode_raw}") from exc

        tick_rate = int(self.replay.header.tick_rate)
        if tick_rate <= 0:
            raise ReplayRunnerError(f"invalid tick_rate: {tick_rate}")
        self.tick_rate = int(tick_rate)
        self.dt = 1.0 / float(self.tick_rate)

        self.world_size = replay.header.world_size if world_size is None else float(world_size)
        spec = msgspec.convert(replay.header, type=RunSpec, from_attributes=True)
        spec = msgspec.structs.replace(spec, world_size=self.world_size)
        try:
            prepared = initialize_run(
                spec,
                apply_world_dt_steps=should_apply_world_dt_steps_for_replay(
                    original_capture_replay=spec.initial_creature_pool is not None,
                ),
                spawn_entries=spawn_entries,
                start_weapon_id=start_weapon_id,
            )
        except ValueError as exc:
            raise ReplayRunnerError(str(exc)) from exc
        self.session = prepared.session
        self.world = self.session.world
        self._terrain_setup = prepared.terrain
        self._quest_definition = prepared.quest
        mode_runtime = self.session.mode_runtime
        self._quest_spawn_state = mode_runtime.spawn if isinstance(mode_runtime, QuestSessionRuntime) else None
        self._quest_total_spawn_count = (
            sum(entry.count for entry in self._quest_spawn_state.spawn_entries) if self._quest_spawn_state is not None else 0
        )
        self._last_tick_rng_rows: tuple[RngTraceDraw, ...] = ()

        self.tick_limit = (
            len(replay.ticks) if self.max_ticks is None else min(len(replay.ticks), max(0, int(self.max_ticks)))
        )

    def _prepare_tick(self, *, tick_index: int) -> None:
        if int(tick_index) < 0 or int(tick_index) >= int(self.tick_limit):
            raise ReplayRunnerError(f"tick_index out of range: {tick_index} (tick_limit={self.tick_limit})")

        state = self.world.state
        state.game_mode = self.mode_id
        state.demo_mode_active = False

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
                int(tick_result.payload.creature_count_world_step) if bool(use_world_step_creature_count) else None
            ),
            deaths=tick_result.payload.events.deaths,
            events=tick_result.payload.events,
        )

    def step_tick(self, tick_index: int) -> TickResult:
        tick_index = int(tick_index)
        self._prepare_tick(tick_index=tick_index)
        self._last_tick_rng_rows = ()
        replay_tick = self.replay.ticks[tick_index]
        dt_tick = float(replay_tick.dt)
        inputs = unpack_tick_inputs(replay_tick.inputs)
        prelude = list(replay_tick.prelude)
        postlude = list(replay_tick.postlude)
        commands: list[GameCommand] = list(replay_tick.commands)
        prelude_post_apply_sfx = self.session.apply_replay_prelude(
            dt=dt_tick,
            operations=prelude,
        )
        with _tick_rng_trace(
            self.world.state.rng,
            enabled=bool(self.trace_rng),
            strict=bool(self.strict_rng_trace),
        ) as tick_rng_rows:
            source_tick = ResolvedTick(
                tick_index=int(tick_index),
                dt_seconds=float(dt_tick),
                inputs=tuple(inputs),
                prelude=tuple(prelude),
                postlude=tuple(postlude),
                commands=tuple(commands),
            )

            session_tick = self.session.step_tick(
                dt=dt_tick,
                inputs=inputs,
                trace_rng=self.trace_rng,
                commands=commands,
                prelude_post_apply_sfx=prelude_post_apply_sfx,
            )
            # These operations occurred inside the native gameplay update,
            # after simulation. Keep the tick RNG sink active so their draws
            # remain at the tail of this tick's canonical stream.
            self.session.apply_replay_postlude(operations=postlude)
            tick_result = TickResult(
                source_tick=source_tick,
                payload=session_tick,
                replay_tick_index=int(tick_index),
            )

        self._last_tick_rng_rows = tuple(tick_rng_rows)
        return tick_result

    def walk_ticks(
        self,
        *,
        start_tick: int = 0,
        stop_tick: int | None = None,
        observer: PlaybackWalkObserver | None = None,
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
        active_observer = observer if observer is not None else PlaybackWalkObserver()

        while next_tick_index < stop_tick_index:
            active_observer.before_tick(
                int(next_tick_index),
                self.world,
                float(self.replay.ticks[next_tick_index].dt),
            )
            tick_result = self.step_tick(next_tick_index)
            next_tick_index = int(tick_result.source_tick.tick_index) + 1

            active_observer.after_tick(tick_result, self.world)
            active_observer.rng_trace(tick_result, self._last_tick_rng_rows)
            active_observer.progress(int(next_tick_index))

        return PlaybackWalkResult(
            start_tick=min(requested_start_tick, tick_limit),
            next_tick_index=int(next_tick_index),
            ticks_completed=int(next_tick_index - min(requested_start_tick, tick_limit)),
        )

    def run(
        self,
        *,
        observer: PlaybackWalkObserver | None = None,
    ) -> RunResult:
        self.walk_ticks(
            start_tick=0,
            stop_tick=int(self.tick_limit),
            observer=observer,
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
