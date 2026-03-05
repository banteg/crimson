from __future__ import annotations

import pytest

from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import InputStatus, NetworkInputProvider
from grim.geom import Vec2


def test_network_provider_stalls_when_runtime_frame_missing() -> None:
    provider = NetworkInputProvider(player_count=2, resolve_tick_input=lambda _tick: None)

    tick_input = provider.pull_tick_input(10)
    assert tick_input.status is InputStatus.STALLED
    assert tick_input.inputs == []


def test_network_provider_uses_runtime_resolved_order_without_remerge() -> None:
    runtime_resolved = [PlayerInput(move=Vec2(3.0, 0.0)), PlayerInput(move=Vec2(4.0, 0.0))]
    provider = NetworkInputProvider(player_count=2, resolve_tick_input=lambda _tick: runtime_resolved)

    tick_input = provider.pull_tick_input(5)

    assert tick_input.status is InputStatus.READY
    assert tick_input.inputs[0].move.x == pytest.approx(3.0)
    assert tick_input.inputs[1].move.x == pytest.approx(4.0)
