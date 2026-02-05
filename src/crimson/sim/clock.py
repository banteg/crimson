from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class FixedStepClock:
    tick_rate: int = 60
    accum: float = 0.0

    def __post_init__(self) -> None:
        tick_rate = int(self.tick_rate)
        if tick_rate <= 0:
            raise ValueError(f"tick_rate must be positive, got {tick_rate}")
        self.tick_rate = tick_rate
        self.accum = float(self.accum)

    @property
    def dt_tick(self) -> float:
        return 1.0 / float(self.tick_rate)

    def reset(self) -> None:
        self.accum = 0.0

    def advance(self, dt: float, *, max_dt: float = 0.1) -> int:
        dt = float(dt)
        if dt <= 0.0:
            return 0
        if dt > float(max_dt):
            dt = float(max_dt)

        self.accum += dt
        dt_tick = float(self.dt_tick)
        if not (dt_tick > 0.0):
            return 0

        ticks = int((self.accum + 1e-9) / dt_tick)
        if ticks <= 0:
            return 0

        self.accum -= dt_tick * float(ticks)
        if self.accum < 0.0:
            self.accum = 0.0
        return int(ticks)

