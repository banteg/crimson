from __future__ import annotations

import pytest

from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import InputStatus, ResolvedTick
from grim.geom import Vec2
from tests.support.builders.input_providers import CallbackInputProvider


def test_network_provider_stalls_when_runtime_frame_missing() -> None:
    provider = CallbackInputProvider(resolve_tick=lambda _tick, _dt: None)

    tick_input = provider.pull_tick(10, 1.0 / 60.0)
    assert tick_input.status is InputStatus.STALLED
    assert tick_input.tick is None


def test_network_provider_uses_runtime_resolved_order_without_remerge() -> None:
    runtime_resolved = [PlayerInput(move=Vec2(3.0, 0.0)), PlayerInput(move=Vec2(4.0, 0.0))]
    provider = CallbackInputProvider(
        resolve_tick=lambda tick, dt: ResolvedTick(
            tick_index=int(tick),
            dt_seconds=float(dt),
            inputs=tuple(runtime_resolved),
            commands=(),
        ),
    )

    tick_input = provider.pull_tick(5, 1.0 / 60.0)

    assert tick_input.status is InputStatus.READY
    assert tick_input.tick is not None
    assert tick_input.tick.inputs[0].move.x == pytest.approx(3.0)
    assert tick_input.tick.inputs[1].move.x == pytest.approx(4.0)
