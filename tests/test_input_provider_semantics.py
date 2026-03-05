from __future__ import annotations

from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import (
    FrameContext,
    InputStatus,
    LocalInputProvider,
    NetworkInputProvider,
)

_FRAME_CTX = FrameContext(
    dt_seconds=1.0 / 60.0,
    tick_dt_seconds=1.0 / 60.0,
    frame_index=1,
    candidate_ticks=1,
)


def test_local_provider_never_stalls_and_clears_edges() -> None:
    provider = LocalInputProvider(
        player_count=1,
        build_inputs=lambda _frame_ctx: [PlayerInput(fire_down=True, fire_pressed=True)],
    )
    provider.begin_frame(_FRAME_CTX)

    first = provider.pull_tick_input(0)
    second = provider.pull_tick_input(1)

    assert first.status is InputStatus.READY
    assert second.status is InputStatus.READY
    assert first.inputs[0].fire_pressed is True
    assert second.inputs[0].fire_pressed is False


def test_local_provider_allows_empty_inputs_for_zero_players() -> None:
    provider = LocalInputProvider(player_count=0, build_inputs=lambda _frame_ctx: [])
    provider.begin_frame(_FRAME_CTX)

    tick0 = provider.pull_tick_input(0)
    assert tick0.status is InputStatus.READY
    assert tick0.inputs == []


def test_network_provider_returns_stalled_when_no_inputs() -> None:
    provider = NetworkInputProvider(player_count=1, resolve_tick_input=lambda tick: None)
    provider.begin_frame(_FRAME_CTX)

    tick0 = provider.pull_tick_input(0)
    assert tick0.status is InputStatus.STALLED
    assert tick0.inputs == []
