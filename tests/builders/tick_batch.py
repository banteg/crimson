from __future__ import annotations

from crimson.sim.hooks import TickResult
from crimson.sim.input_providers import InputStatus
from crimson.sim.tick_runner import TickBatchResult


def make_tick_batch(
    *,
    ticks: list[TickResult] | None = None,
    status: InputStatus = InputStatus.READY,
    next_tick_index: int | None = None,
) -> TickBatchResult:
    ticks = ticks or []
    completed = len(ticks)
    if next_tick_index is None:
        next_tick_index = (ticks[-1].tick_index + 1) if ticks else 0
    return TickBatchResult(
        ticks_completed=completed,
        batch_status=status,
        next_tick_index=next_tick_index,
        completed_results=ticks,
    )
