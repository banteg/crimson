from __future__ import annotations

import msgspec

from .sessions import DeterministicSessionTick


class TickResult(msgspec.Struct, frozen=True):
    tick_index: int
    payload: DeterministicSessionTick
