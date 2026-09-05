from __future__ import annotations

import msgspec

from .input_providers import ResolvedTick
from .sessions import DeterministicSessionTick


class TickResult(msgspec.Struct):
    source_tick: ResolvedTick
    payload: DeterministicSessionTick
    replay_tick_index: int | None = None
