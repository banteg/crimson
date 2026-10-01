from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import msgspec

from grim.rand import CallerStatic, CrandLike, CrtRand, RecordedCallerStatic, RngTraceSink

from ...game_modes import GameMode
from ...quests.types import QuestDefinition, SpawnEntry
from ...replay import REPLAY_TICK_DT, Replay, warn_on_game_version_mismatch
from ...replay.checkpoints import ReplayCheckpoint
from ...replay.checkpoints import build_checkpoint as build_replay_checkpoint
from ...replay.rng_call_order import RngCallOrder
from ...replay.ticks import step_replay_tick
from ...sim.hooks import TickResult
from ...sim.mode_updates import QuestSpawnState
from ...sim.run_init import initialize_run
from ...sim.run_result import RunDown, RunOutcome, RunResult, build_run_result
from ...sim.sessions import IllegalCommandError
from ...sim.terrain_generate import TerrainSetup
from ...sim.world_state import WorldState
from ...weapons import WeaponId
from .setup import ReplayRunnerError

type RngTraceDraw = tuple[int, int, int, RecordedCallerStatic]


@contextmanager
def _tick_rng_trace(
    rng: CrandLike,
    call_order: RngCallOrder,
    *,
    enabled: bool,
    strict: bool = False,
) -> Iterator[list[RngTraceDraw]]:
    """Record the tick's caller order for its checkpoint and, when enabled, every draw."""

    draws: list[RngTraceDraw] = []
    with call_order.recording(rng):
        if not enabled:
            yield draws
            return
        assert isinstance(rng, CrtRand)

        def _sink(
            state_before_u32: int,
            state_after_u32: int,
            value_15: int,
            caller: CallerStatic | None,
        ) -> None:
            call_order(state_before_u32, state_after_u32, value_15, caller)
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
        yield draws


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
    """Step a deterministic session through a replay's recorded ticks exactly as live play does."""

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
        self.run_spec = replay.run
        self.mode_id = GameMode(replay.run.game_mode_id)
        self.tick_count = len(replay.ticks)
        self.max_ticks = max_ticks
        self.trace_rng = bool(trace_rng)
        self.strict_rng_trace = bool(strict_rng_trace)
        self._run_down: RunDown | None = None

        try:
            prepared = initialize_run(
                self.run_spec,
                spawn_entries=spawn_entries,
                start_weapon_id=start_weapon_id,
            )
        except ValueError as exc:
            raise ReplayRunnerError(str(exc)) from exc
        self.session = prepared.session
        self.world = self.session.world
        self._terrain_setup = prepared.terrain
        self._quest_definition = prepared.quest
        mode_state = self.session.mode_state
        self._quest_spawn_state = mode_state if isinstance(mode_state, QuestSpawnState) else None
        self._last_tick_rng_rows: tuple[RngTraceDraw, ...] = ()
        # The caller tags of the last stepped tick's draws, in order.
        self.rng_call_order = RngCallOrder()

        self.tick_limit = self.tick_count if self.max_ticks is None else min(self.tick_count, max(0, int(self.max_ticks)))

    def build_checkpoint(
        self,
        *,
        tick_result: TickResult,
        use_world_step_creature_count: bool = False,
    ) -> ReplayCheckpoint:
        return build_replay_checkpoint(
            tick_index=int(tick_result.tick_index),
            world=self.world,
            elapsed_ms=float(self.elapsed_ms),
            rng_callers_crc32=self.rng_call_order.crc32(),
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
        try:
            with _tick_rng_trace(
                self.world.state.rng,
                self.rng_call_order,
                enabled=bool(self.trace_rng),
                strict=bool(self.strict_rng_trace),
            ) as tick_rng_rows:
                session_tick = step_replay_tick(self.session, self.replay.ticks[tick_index])
        except IllegalCommandError as exc:
            raise ReplayRunnerError(f"tick {tick_index}: {exc}") from exc
        outcome = session_tick.outcome
        if self._run_down is None and outcome is not None:
            self._run_down = RunDown(outcome=outcome, end_tick=tick_index)
        run_down = self._run_down
        if run_down is not None and run_down.tick(session_tick.timing.frame_dt_ms_i32) and tick_index < self.tick_count - 1:
            raise ReplayRunnerError(
                f"run ended ({run_down.outcome}) at tick {run_down.end_tick} and wound down by tick {tick_index} "
                f"but the replay has {self.tick_count} ticks",
            )
        self._last_tick_rng_rows = tuple(tick_rng_rows)
        return TickResult(tick_index=tick_index, payload=session_tick)

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
            active_observer.before_tick(int(next_tick_index), self.world, REPLAY_TICK_DT)
            tick_result = self.step_tick(next_tick_index)
            next_tick_index = int(tick_result.tick_index) + 1

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
    spawn_entries: tuple[SpawnEntry, ...] | None = None,
    start_weapon_id: WeaponId | None = None,
) -> PlaybackDriver:
    """Build the canonical live replay-playback driver."""

    return PlaybackDriver(
        replay,
        max_ticks=max_ticks,
        version_mismatch_action=None,
        spawn_entries=spawn_entries,
        start_weapon_id=start_weapon_id,
    )
