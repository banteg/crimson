from __future__ import annotations

from crimson.sim.hooks import TickResult
from crimson.sim.sessions import DeterministicSessionTick

from .tick_payload import make_tick_payload


def make_tick_result(
    *,
    tick_index: int = 0,
    command_hash: str = "cmd-hash",
    dt_sim: float = 1.0 / 60.0,
    payload: DeterministicSessionTick | None = None,
) -> TickResult:
    if payload is None:
        payload = make_tick_payload(command_hash=command_hash, dt_sim=dt_sim)
    return TickResult(
        tick_index=tick_index,
        command_hash=command_hash,
        dt_sim=dt_sim,
        presentation_plan_ms=0.0,
        payload=payload,
    )
