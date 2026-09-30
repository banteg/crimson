"""Per-tick digest of the order in which RNG call sites drew.

Checkpoints pin the RNG state after every tick, which catches a changed number of draws but not draws
reordered within a tick: an LCG lands on the same state whichever call site draws first. Each checkpoint
also carries a CRC32 of the tick's ordered call-site tags, so a reorder fails at its tick.
"""

from __future__ import annotations

import struct
import zlib
from collections.abc import Iterator, Sequence
from contextlib import contextmanager

from grim.rand import CrandLike, CrtRand, RecordedCallerStatic

from ..rng_caller_static import RngCallerStatic

UNTAGGED_CALLER = 0xFFFFFFFF
_CALLER_NAMES = {int(member): member.name for member in RngCallerStatic}


def callers_crc32(callers: Sequence[int]) -> int:
    """CRC32 of the caller tags packed as little-endian uint32s, in draw order."""

    return zlib.crc32(struct.pack(f"<{len(callers)}I", *callers))


def caller_names(callers: Sequence[int]) -> list[str]:
    return [
        _CALLER_NAMES.get(caller, "UNTAGGED" if caller == UNTAGGED_CALLER else f"0x{caller:08x}") for caller in callers
    ]


class RngCallOrder:
    """The caller tags of one tick's draws, in order; untagged draws record `UNTAGGED_CALLER`.

    It is the RNG's trace sink while a tick runs under `recording`, and keeps the tick's tags until the next
    tick starts.
    """

    __slots__ = ("callers",)

    def __init__(self) -> None:
        self.callers: list[int] = []

    def __call__(self, _state_before: int, _state_after: int, _value: int, caller: RecordedCallerStatic) -> None:
        self.callers.append(UNTAGGED_CALLER if caller is None else caller)

    @contextmanager
    def recording(self, rng: CrandLike) -> Iterator[None]:
        assert isinstance(rng, CrtRand), f"RNG call order needs a traceable CrtRand, got {type(rng).__name__}"
        self.callers.clear()
        previous_sink = rng.trace_sink
        previous_require_caller = rng.trace_require_caller
        rng.set_trace_sink(self)
        try:
            yield
        finally:
            rng.set_trace_sink(previous_sink, require_caller=previous_require_caller)

    def crc32(self) -> int:
        return callers_crc32(self.callers)
