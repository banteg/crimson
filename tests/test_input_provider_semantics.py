from __future__ import annotations

import pytest

from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import (
    FrameContext,
    LocalInputProvider,
    NetworkInputProvider,
    ReplayEndOfStream,
    ReplayInputProvider,
)


def test_local_provider_never_stalls_and_clears_edges() -> None:
    provider = LocalInputProvider(
        player_count=1,
        build_inputs=lambda: [PlayerInput(fire_down=True, fire_pressed=True)],
    )
    provider.begin_frame(FrameContext(player_count=1))

    first = provider.pull_tick_input(0)
    second = provider.pull_tick_input(1)

    assert first is not None
    assert second is not None
    assert first[0].fire_pressed is True
    assert second[0].fire_pressed is False


def test_local_provider_rejects_empty_inputs_when_players_exist() -> None:
    provider = LocalInputProvider(player_count=1, build_inputs=lambda: [])

    with pytest.raises(ValueError, match="empty input list"):
        provider.begin_frame(FrameContext(player_count=1))


def test_local_provider_allows_empty_inputs_for_zero_players() -> None:
    provider = LocalInputProvider(player_count=0, build_inputs=lambda: [])
    provider.begin_frame(FrameContext(player_count=0))

    assert provider.pull_tick_input(0) == []


def test_replay_provider_uses_eos_exception_not_stall_none() -> None:
    provider = ReplayInputProvider(player_count=1, tick_inputs=[[PlayerInput()]])
    provider.begin_frame(FrameContext(player_count=1, is_replay=True))

    tick0 = provider.pull_tick_input(0)
    assert tick0 is not None

    with pytest.raises(ReplayEndOfStream):
        provider.pull_tick_input(1)


def test_network_provider_allows_stall_none_and_rejects_empty_nonzero() -> None:
    rows: dict[int, list[PlayerInput] | None] = {
        0: None,
        1: [],
    }
    provider = NetworkInputProvider(player_count=1, resolve_tick_input=lambda tick: rows.get(tick))
    provider.begin_frame(FrameContext(player_count=1, is_networked=True))

    assert provider.pull_tick_input(0) is None
    with pytest.raises(ValueError, match="empty input list"):
        provider.pull_tick_input(1)
