"""Per-tick RNG call-order goldens for recorded replays.

Checkpoints pin the RNG state after every tick, which catches a changed number of
draws but not draws reordered within a tick: an LCG lands on the same state
whichever call site draws first. These goldens pin, for every tick, a CRC32 of the
ordered call-site tags that drew, so a reorder fails at its tick and names its callers.
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

import zstandard

from crimson.replay import Replay
from crimson.replay.driver.playback_driver import PlaybackWalkObserver, RngTraceDraw, build_verify_playback_driver
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.hooks import TickResult

_UNTAGGED = 0xFFFFFFFF


def golden_path(replay_path: Path) -> Path:
    return replay_path.with_name(f"{replay_path.name}.rng")


def tick_callers(draws: tuple[RngTraceDraw, ...]) -> list[int]:
    return [_UNTAGGED if caller is None else int(caller) for *_state, caller in draws]


def callers_digest(callers: list[int]) -> int:
    return zlib.crc32(struct.pack(f"<{len(callers)}I", *callers))


def caller_names(callers: list[int]) -> list[str]:
    known = {int(member): member.name for member in RngCallerStatic}
    return [known.get(caller, "UNTAGGED" if caller == _UNTAGGED else f"0x{caller:08x}") for caller in callers]


class _CallOrderObserver(PlaybackWalkObserver):
    callers_by_tick: list[list[int]]

    def rng_trace(self, tick_result: TickResult, draws: tuple[RngTraceDraw, ...]) -> None:
        assert int(tick_result.tick_index) == len(self.callers_by_tick)
        self.callers_by_tick.append(tick_callers(draws))


def record_call_order(replay: Replay) -> list[list[int]]:
    driver = build_verify_playback_driver(replay, trace_rng=True, warn_on_version_mismatch=False)
    observer = _CallOrderObserver(callers_by_tick=[])
    driver.walk_ticks(start_tick=0, stop_tick=int(driver.tick_limit), observer=observer)
    return observer.callers_by_tick


def write_golden(path: Path, callers_by_tick: list[list[int]]) -> None:
    digests = [callers_digest(callers) for callers in callers_by_tick]
    raw = struct.pack(f"<{len(digests)}I", *digests)
    path.write_bytes(zstandard.ZstdCompressor(level=19).compress(raw))


def read_golden(path: Path) -> list[int]:
    raw = zstandard.ZstdDecompressor().decompress(path.read_bytes())
    return list(struct.unpack(f"<{len(raw) // 4}I", raw))
