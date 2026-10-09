"""Preparing a replay for the viewer (docs/rewrite/replay-viewer.md).

A pass plays the whole recording undrawn and keeps what seeking needs: a keyframe every half second (the driver's
state, zstd-packed), every bake into the terrain in order, and the scrub bar's marks (Survival's milestone waves,
Energizer drops, perk picks with the menu's offers) and the tunes the run starts. The native viewer prepares a run
before it plays; the Python simulation plays a 9-minute Survival run in about a minute, so the port prepares in a
process of its own while the replay already plays, and the viewer seeks anywhere the pass has reached.
"""

from __future__ import annotations

import bisect
import multiprocessing
import pickle
from collections.abc import Iterator
from enum import IntEnum
from multiprocessing.connection import Connection

import msgspec
import zstandard as zstd

from grim.geom import Vec2
from grim.rand import Crand

from ...bonuses.ids import BonusId
from ...camera import camera_update_for_players
from ...perks.selection import PerkPick
from ...sim.clock import PresentationClock
from ...sim.mode_updates import SurvivalSpawnState
from ...sim.run_result import RunOutcome
from ...sim.sessions import DeterministicSessionTick
from ...sim.terrain_fx import TerrainFxBatch
from ..types import Replay
from .playback_driver import PlaybackDriver, build_runtime_playback_driver
from .setup import ReplayRunnerError

# Keyframes start half a second apart and spread out, every other one dropped, past the budget.
KEY_TICKS = 30
KEY_BYTES = 256 << 20


class Keyframe(msgspec.Struct, frozen=True):
    tick: int  # ticks played before it
    bakes: int  # bakes into the terrain before it
    state: bytes  # the driver's, zstd-packed
    clock: PresentationClock
    # Where the camera last followed the players: it holds there once they are dead.
    focus: Vec2 | None


class MarkKind(IntEnum):
    WAVE = 0  # a Survival milestone wave: its spawn stage
    ENERGIZER = 1  # an Energizer drop: its bonus slot
    PICK = 2  # a perk pick: its index in the picks


class Mark(msgspec.Struct, frozen=True):
    tick: int
    kind: MarkKind
    value: int


class Pick(msgspec.Struct, frozen=True):
    """A perk pick as the menu showed it, the tick after it and the level it came with."""

    tick: int
    level: int
    pick: PerkPick


class Tune(msgspec.Struct, frozen=True):
    """A tune the run starts after `tick` ticks: a named track, or the game playlist's entry its `draw` picks."""

    tick: int
    track: str = ""
    draw: int = 0
    fade_in: bool = False


class PreparedSpan(msgspec.Struct, frozen=True):
    """What the pass found since its last span, up to `tick` ticks; the last span carries how the run ends."""

    tick: int
    key: Keyframe | None
    bakes: bytes  # the span's bakes into the terrain, in order, zstd-packed
    bake_count: int
    marks: tuple[Mark, ...] = ()
    picks: tuple[Pick, ...] = ()
    tunes: tuple[Tune, ...] = ()
    # The last span: the ticks the run plays, and why it stops before the recording's end.
    ended: bool = False
    stopped: str = ""


def _pack_bakes(bakes: list[TerrainFxBatch]) -> bytes:
    return zstd.ZstdCompressor(level=1).compress(pickle.dumps(tuple(bakes), protocol=pickle.HIGHEST_PROTOCOL))


def _unpack_bakes(packed: bytes) -> tuple[TerrainFxBatch, ...]:
    return pickle.loads(zstd.ZstdDecompressor().decompress(packed))


def restore_keyframe(driver: PlaybackDriver, key: Keyframe) -> None:
    driver.restore(zstd.ZstdDecompressor().decompress(key.state))


class _PreparingPass:
    """The pass over a replay, and what it found since its last span."""

    def __init__(self, replay: Replay, *, key_ticks: int) -> None:
        self._driver = build_runtime_playback_driver(replay, max_ticks=None)
        self._key_ticks = key_ticks
        self._clock = PresentationClock()
        # The game playlist's draws, from the replay's own sound randomness.
        self._tune_rng = Crand(int(replay.run.seed) & 0xFFFFFFFF)
        self._bakes: list[TerrainFxBatch] = []
        self._bake_total = 0
        self._marks: list[Mark] = []
        self._picks: list[Pick] = []
        self._pick_total = 0
        self._tunes: list[Tune] = []
        self._stage = self._survival_stage()
        self._energizers = self._energizer_slots()
        self._focus = self._players_focus()

    def _survival_stage(self) -> int | None:
        mode_state = self._driver.session.mode_state
        return mode_state.stage if isinstance(mode_state, SurvivalSpawnState) else None

    def _energizer_slots(self) -> list[bool]:
        pool = self._driver.world.state.bonus_pool
        return [entry.bonus_id == BonusId.ENERGIZER and not entry.picked for entry in pool.entries]

    def _players_focus(self) -> Vec2 | None:
        return camera_update_for_players(self._driver.world.players, Vec2()).focus

    def run(self) -> Iterator[PreparedSpan]:
        driver = self._driver
        yield self._span(0, key=True)
        for tick in range(driver.tick_limit):
            try:
                result = driver.step_tick(tick)
            except ReplayRunnerError:
                yield self._span(tick, key=False, ended=True, stopped=f"This run stops playing here (tick {tick})")
                return
            self._note(tick + 1, result.payload)
            if (tick + 1) % self._key_ticks == 0:
                yield self._span(tick + 1, key=True)
        # A death ends on the game over screen and its tune.
        if driver.session.end_outcome() == RunOutcome.DEATH:
            self._tunes.append(Tune(driver.tick_limit, "shortie_monk"))
        yield self._span(driver.tick_limit, key=False, ended=True)

    def _note(self, played: int, payload: DeterministicSessionTick) -> None:
        """What the tick that brought the run to `played` ticks did."""
        self._clock.advance(payload.dt_sim)
        self._focus = self._players_focus() or self._focus
        plan = payload.presentation
        if not plan.terrain_fx.is_empty():
            self._bakes.append(plan.terrain_fx)
        level = self._driver.world.players[0].level
        for pick in payload.perk_picks:
            self._marks.append(Mark(played, MarkKind.PICK, self._pick_total + len(self._picks)))
            self._picks.append(Pick(played, level, pick))
        stage = self._survival_stage()
        if stage is not None and stage != self._stage:
            self._marks.append(Mark(played, MarkKind.WAVE, stage))
        self._stage = stage
        energizers = self._energizer_slots()
        for slot, energizer in enumerate(energizers):
            if energizer and not self._energizers[slot]:
                self._marks.append(Mark(played, MarkKind.ENERGIZER, slot))
        self._energizers = energizers
        if plan.trigger_game_tune:
            self._tunes.append(Tune(played, draw=self._tune_rng.rand()))
        if plan.play_quest_completion_music:
            self._tunes.append(Tune(played, "crimsonquest", fade_in=True))

    def _span(self, tick: int, *, key: bool, ended: bool = False, stopped: str = "") -> PreparedSpan:
        bakes = self._bakes
        keyframe = None
        if key:
            state = zstd.ZstdCompressor(level=1).compress(self._driver.keyframe_state())
            keyframe = Keyframe(
                tick, self._bake_total + len(bakes), state, msgspec.structs.replace(self._clock), self._focus,
            )
        span = PreparedSpan(
            tick, keyframe, _pack_bakes(bakes) if bakes else b"", len(bakes),
            tuple(self._marks), tuple(self._picks), tuple(self._tunes), ended, stopped,
        )
        self._bake_total += len(bakes)
        self._pick_total += len(self._picks)
        for found in (bakes, self._marks, self._picks, self._tunes):
            found.clear()
        return span


def prepare_replay(replay: Replay, *, key_ticks: int = KEY_TICKS) -> Iterator[PreparedSpan]:
    """The preparing pass, a span at each keyframe."""
    return _PreparingPass(replay, key_ticks=key_ticks).run()


def _prepare_in_process(replay: Replay, conn: Connection) -> None:
    try:
        for span in prepare_replay(replay):
            conn.send(span)
    except (BrokenPipeError, EOFError):
        # The viewer closed.
        pass


class BakeLog:
    """Every bake into the terrain the pass sent, in order, zstd-packed a span at a time."""

    def __init__(self) -> None:
        self._starts: list[int] = []
        self._packed: list[bytes] = []
        self.count = 0
        # The span last read, unpacked.
        self._open_index = -1
        self._open: tuple[TerrainFxBatch, ...] = ()

    def append(self, packed: bytes, count: int) -> None:
        if count:
            self._starts.append(self.count)
            self._packed.append(packed)
            self.count += count

    def read(self, start: int, stop: int) -> Iterator[TerrainFxBatch]:
        """The bakes from `start` up to `stop`."""
        at = start
        while at < stop:
            index = bisect.bisect_right(self._starts, at) - 1
            if self._open_index != index:
                self._open_index, self._open = index, _unpack_bakes(self._packed[index])
            batches = self._open
            first = self._starts[index]
            end = min(stop, first + len(batches))
            yield from batches[at - first : end - first]
            at = end


class ReplayPreparation:
    """The preparing pass, in a process of its own or in this one, and what it has found so far."""

    def __init__(self, replay: Replay, *, background: bool = True) -> None:
        self.keys: list[Keyframe] = []
        self._key_bytes = 0
        self.bakes = BakeLog()
        self.marks: list[Mark] = []
        self.picks: list[Pick] = []
        self.tunes: list[Tune] = []
        self.tick = 0  # ticks the pass has played
        self.ended = False
        self.stopped = ""
        self._process: multiprocessing.process.BaseProcess | None = None
        self._conn: Connection | None = None
        self._inline: Iterator[PreparedSpan] | None = None
        if not background:
            self._inline = prepare_replay(replay)
            return
        context = multiprocessing.get_context("spawn")
        self._conn, child = context.Pipe(duplex=False)
        self._process = context.Process(
            target=_prepare_in_process, args=(replay, child), name="crimson-replay-prepare", daemon=True,
        )
        self._process.start()
        child.close()

    def poll(self) -> bool:
        """Takes what the pass has sent (in this process, plays it whole); whether anything came."""
        came = False
        if self._inline is not None:
            for span in self._inline:
                self._take(span)
                came = True
            self._inline = None
        conn = self._conn
        while conn is not None and not self.ended and conn.poll():
            try:
                self._take(conn.recv())
            except EOFError:
                # The pass died before the end: what it sent stays.
                self.close()
                break
            came = True
        return came

    def wait(self) -> None:
        """Blocks until the pass reaches the run's end."""
        while not self.ended and (self._conn is not None or self._inline is not None):
            if self._conn is not None:
                self._conn.poll(None)
            self.poll()

    def _take(self, span: PreparedSpan) -> None:
        self.bakes.append(span.bakes, span.bake_count)
        self.marks.extend(span.marks)
        self.picks.extend(span.picks)
        self.tunes.extend(span.tunes)
        self.tick = span.tick
        if span.key is not None:
            self.keys.append(span.key)
            self._key_bytes += len(span.key.state)
            # Past the budget, every other keyframe goes.
            while self._key_bytes > KEY_BYTES and len(self.keys) > 2:
                self.keys = self.keys[::2]
                self._key_bytes = sum(len(key.state) for key in self.keys)
        if span.ended:
            self.ended = True
            self.stopped = span.stopped
            self.close()

    def key_before(self, tick: int) -> Keyframe | None:
        """The last keyframe before `tick`."""
        index = bisect.bisect_left(self.keys, tick, key=lambda key: key.tick) - 1
        return self.keys[index] if index >= 0 else None

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
        if self._process is not None:
            if self._process.is_alive():
                self._process.terminate()
            self._process.join(timeout=1.0)
            self._process = None
        self._inline = None
