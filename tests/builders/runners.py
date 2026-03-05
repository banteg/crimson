from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from crimson.sim.hooks import TickResult
from crimson.sim.input_providers import InputStatus
from crimson.sim.tick_runner import TickBatchResult


@dataclass
class FakeRunner:
    """Configurable fake tick runner for orchestration tests.

    When ``results`` is non-empty, pops the first result on each advance.
    Otherwise generates a default batch from ``ticks_requested``.
    """

    results: list[TickBatchResult] = field(default_factory=list)
    frame_count: int = 0
    calls: int = 0
    on_advance: Callable[[], None] | None = None

    def begin_frame(self, frame_ctx: object) -> None:
        _ = frame_ctx
        self.frame_count += 1

    def advance_ticks(self, *, start_tick: int, ticks_requested: int, tick_dt: float) -> TickBatchResult:
        _ = tick_dt
        self.calls += 1
        if self.on_advance is not None:
            self.on_advance()
        if self.results:
            result = self.results.pop(0)
            result.next_tick_index = int(start_tick) + int(result.ticks_completed)
            return result
        ticks = max(0, int(ticks_requested))
        rows = [
            TickResult(
                tick_index=int(start_tick + i),
                dt_sim=1.0 / 60.0,
                payload=object(),
            )
            for i in range(int(ticks))
        ]
        return TickBatchResult(
            ticks_completed=int(ticks),
            batch_status=InputStatus.READY,
            next_tick_index=int(start_tick) + int(ticks),
            completed_results=rows,
        )
