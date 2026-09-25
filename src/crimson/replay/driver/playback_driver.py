from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import msgspec

from grim.rand import CallerStatic, CrtRand, RecordedCallerStatic, RngTraceSink
from grim.sfx_map import SfxId

from ...game_modes import GameMode
from ...quests import quest_by_level
from ...quests.types import QuestDefinition, SpawnEntry
from ...replay import REPLAY_TICK_DT, Replay, ReplayRecorder, warn_on_game_version_mismatch
from ...replay.checkpoints import ReplayCheckpoint
from ...replay.checkpoints import build_checkpoint as build_replay_checkpoint
from ...replay.input_codec import unpack_tick_inputs
from ...sim.bootstrap import TerrainSetup
from ...sim.hooks import TickResult
from ...sim.input import PlayerInput
from ...sim.input_providers import GameCommand, ResolvedTick
from ...sim.run_init import initialize_run
from ...sim.run_result import RunOutcome, RunResult, build_run_result
from ...sim.run_spec import WORLD_SIZE, RunSpec
from ...sim.sessions import (
    IllegalCommandError,
    QuestSessionRuntime,
    QuestSpawnState,
)
from ...sim.world_reset import CreatureSlotResidue
from ...sim.world_state import WorldState
from ...weapons import WeaponId
from .setup import ReplayRunnerError

type RngTraceDraw = tuple[int, int, int, RecordedCallerStatic]


def resolve_quest_definition(run: RunSpec) -> QuestDefinition:
    if run.quest_level is None:
        raise ReplayRunnerError("quest replays require a quest_level")
    quest = quest_by_level(run.quest_level)
    if quest is None:
        raise ReplayRunnerError(f"unsupported quest replay: unknown quest_level={run.quest_level.text!r}")
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


class SessionPlaybackDriver:
    """Step a deterministic session through an indexed tick source.

    Subclasses supply each tick's delta, inputs and commands. The replay
    driver below is the canonical source; debug tooling layers original-capture
    playback on the `before_tick`/`after_step` hooks.
    """

    def __init__(
        self,
        run: RunSpec,
        *,
        tick_count: int,
        max_ticks: int | None = None,
        trace_rng: bool = False,
        strict_rng_trace: bool = False,
        spawn_entries: tuple[SpawnEntry, ...] | None = None,
        start_weapon_id: WeaponId | None = None,
        apply_world_dt_steps: bool = True,
        creature_pool_residue: tuple[CreatureSlotResidue, ...] | None = None,
        strict_end: bool = True,
        strict_commands: bool = True,
    ) -> None:
        self.run_spec = run
        self.mode_id = GameMode(run.game_mode_id)
        self.world_size = WORLD_SIZE
        self.tick_count = int(tick_count)
        self.max_ticks = max_ticks
        self.trace_rng = bool(trace_rng)
        self.strict_rng_trace = bool(strict_rng_trace)
        self.strict_end = bool(strict_end)

        try:
            prepared = initialize_run(
                self.run_spec,
                apply_world_dt_steps=apply_world_dt_steps,
                creature_pool_residue=creature_pool_residue,
                spawn_entries=spawn_entries,
                start_weapon_id=start_weapon_id,
            )
        except ValueError as exc:
            raise ReplayRunnerError(str(exc)) from exc
        self.session = prepared.session
        self.session.strict_commands = bool(strict_commands)
        self.world = self.session.world
        self._terrain_setup = prepared.terrain
        self._quest_definition = prepared.quest
        mode_runtime = self.session.mode_runtime
        self._quest_spawn_state = mode_runtime.spawn if isinstance(mode_runtime, QuestSessionRuntime) else None
        self._quest_total_spawn_count = (
            sum(entry.count for entry in self._quest_spawn_state.spawn_entries) if self._quest_spawn_state is not None else 0
        )
        self._last_tick_rng_rows: tuple[RngTraceDraw, ...] = ()

        self.tick_limit = self.tick_count if self.max_ticks is None else min(self.tick_count, max(0, int(self.max_ticks)))

    def tick_dt(self, tick_index: int) -> float:
        raise NotImplementedError

    def tick_inputs(self, tick_index: int) -> list[PlayerInput]:
        raise NotImplementedError

    def tick_commands(self, tick_index: int) -> list[GameCommand]:
        raise NotImplementedError

    def before_tick(self, tick_index: int) -> list[SfxId]:
        """Apply work between ticks, outside the tick RNG trace; returns SFX to emit with the tick."""

        _ = tick_index
        return []

    def after_step(self, tick_index: int) -> None:
        """Apply work after simulation, inside the tick RNG trace."""

        _ = tick_index

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
        if tick_index < 0 or tick_index >= int(self.tick_limit):
            raise ReplayRunnerError(f"tick_index out of range: {tick_index} (tick_limit={self.tick_limit})")
        self.world.state.game_mode = self.mode_id
        self._last_tick_rng_rows = ()
        dt_tick = float(self.tick_dt(tick_index))
        inputs = self.tick_inputs(tick_index)
        commands = self.tick_commands(tick_index)
        try:
            pending_sfx = self.before_tick(tick_index)
            with _tick_rng_trace(
                self.world.state.rng,
                enabled=bool(self.trace_rng),
                strict=bool(self.strict_rng_trace),
            ) as tick_rng_rows:
                session_tick = self.session.step_tick(
                    dt=dt_tick,
                    inputs=inputs,
                    trace_rng=self.trace_rng,
                    commands=commands,
                    prelude_post_apply_sfx=pending_sfx,
                )
                self.after_step(tick_index)
        except IllegalCommandError as exc:
            raise ReplayRunnerError(f"tick {tick_index}: {exc}") from exc
        outcome = session_tick.outcome
        if self.strict_end and outcome is not None and tick_index < self.tick_count - 1:
            raise ReplayRunnerError(
                f"run ended ({outcome}) at tick {tick_index} but the replay has {self.tick_count} ticks",
            )
        self._last_tick_rng_rows = tuple(tick_rng_rows)
        return TickResult(
            source_tick=ResolvedTick(
                tick_index=tick_index,
                dt_seconds=dt_tick,
                inputs=tuple(inputs),
                commands=tuple(commands),
            ),
            payload=session_tick,
            replay_tick_index=tick_index,
        )

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
            active_observer.before_tick(int(next_tick_index), self.world, float(self.tick_dt(next_tick_index)))
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

    def run(self, *, observer: PlaybackWalkObserver | None = None) -> RunResult:
        self.walk_ticks(start_tick=0, stop_tick=int(self.tick_limit), observer=observer)
        return self.build_result()

    @property
    def complete(self) -> bool:
        """Whether every recorded tick was simulated (no `max_ticks` prefix)."""

        return int(self.tick_limit) == int(self.tick_count)

    def build_result(self) -> RunResult:
        """Result after the simulated ticks; a prefix only reports a terminal outcome it reached."""

        if self.complete:
            outcome = self.session.end_outcome()
        else:
            outcome = self.session.terminal_outcome() or RunOutcome.INCOMPLETE
        return build_run_result(self.session, outcome=outcome)

    @property
    def elapsed_ms(self) -> float:
        return self.session.run_elapsed_ms

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


class PlaybackDriver(SessionPlaybackDriver):
    """Canonical replay driver."""

    def __init__(
        self,
        replay: Replay,
        *,
        max_ticks: int | None = None,
        trace_rng: bool = False,
        strict_rng_trace: bool = False,
        version_mismatch_action: str | None = "verification",
        spawn_entries: tuple[SpawnEntry, ...] | None = None,
        start_weapon_id: WeaponId | None = None,
    ) -> None:
        if version_mismatch_action is not None:
            warn_on_game_version_mismatch(replay, action=str(version_mismatch_action))
        self.replay = replay
        super().__init__(
            replay.run,
            tick_count=len(replay.ticks),
            max_ticks=max_ticks,
            trace_rng=trace_rng,
            strict_rng_trace=strict_rng_trace,
            spawn_entries=spawn_entries,
            start_weapon_id=start_weapon_id,
        )

    def tick_dt(self, tick_index: int) -> float:
        _ = tick_index
        return REPLAY_TICK_DT

    def tick_inputs(self, tick_index: int) -> list[PlayerInput]:
        return unpack_tick_inputs(self.replay.ticks[tick_index].inputs)

    def tick_commands(self, tick_index: int) -> list[GameCommand]:
        return list(self.replay.ticks[tick_index].commands)


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
    spawn_entries: tuple[SpawnEntry, ...] | None = None,
    start_weapon_id: WeaponId | None = None,
) -> PlaybackDriver:
    """Build the canonical live replay-playback driver."""

    return PlaybackDriver(
        replay,
        max_ticks=max_ticks,
        trace_rng=bool(trace_rng),
        version_mismatch_action=None,
        spawn_entries=spawn_entries,
        start_weapon_id=start_weapon_id,
    )


def replay_with_simulated_result(replay: Replay) -> Replay:
    """Return `replay` carrying the result its ticks simulate to (for tools and tests that synthesize inputs)."""

    result = build_verify_playback_driver(replay, warn_on_version_mismatch=False).run()
    return msgspec.structs.replace(replay, result=result)


def finish_with_simulated_result(recorder: ReplayRecorder) -> Replay:
    """Finish a synthesized recording with the result its ticks simulate to."""

    unverified = RunResult(
        outcome=RunOutcome.INCOMPLETE,
        elapsed_ms=0,
        kills=0,
        rng_state=0,
        pending_perks=0,
        quest_final_ms=None,
        players=(),
    )
    return replay_with_simulated_result(recorder.finish(unverified))
