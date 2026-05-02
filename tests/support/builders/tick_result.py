from __future__ import annotations

from crimson.sim.hooks import TickResult
from crimson.sim.input_providers import ResolvedTick
from crimson.sim.sessions import DeterministicSessionTick

from .tick_payload import make_tick_payload


def make_tick_result(
    *,
    tick_index: int = 0,
    dt_sim: float = 1.0 / 60.0,
    payload: DeterministicSessionTick | None = None,
    replay_tick_index: int | None = None,
) -> TickResult:
    if payload is None:
        payload = make_tick_payload(dt_sim=dt_sim)
    return TickResult(
        source_tick=ResolvedTick(
            tick_index=int(tick_index),
            dt_seconds=float(dt_sim),
            inputs=(),
            commands=(),
        ),
        payload=payload,
        replay_tick_index=(int(tick_index) if replay_tick_index is None else int(replay_tick_index)),
    )
