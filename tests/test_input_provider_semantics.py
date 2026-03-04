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

_FRAME_CTX = FrameContext(
    dt_seconds=1.0 / 60.0,
    tick_dt_seconds=1.0 / 60.0,
    frame_index=1,
    candidate_ticks=1,
)


def test_local_provider_never_stalls_and_clears_edges() -> None:
    provider = LocalInputProvider(
        player_count=1,
        build_inputs=lambda: [PlayerInput(fire_down=True, fire_pressed=True)],
    )
    provider.begin_frame(_FRAME_CTX)

    first = provider.pull_tick_input(0)
    second = provider.pull_tick_input(1)

    assert first is not None
    assert second is not None
    assert first[0].fire_pressed is True
    assert second[0].fire_pressed is False


def test_local_provider_rejects_empty_inputs_when_players_exist() -> None:
    provider = LocalInputProvider(player_count=1, build_inputs=lambda: [])

    with pytest.raises(ValueError, match="empty input list"):
        provider.begin_frame(_FRAME_CTX)


def test_local_provider_allows_empty_inputs_for_zero_players() -> None:
    provider = LocalInputProvider(player_count=0, build_inputs=lambda: [])
    provider.begin_frame(_FRAME_CTX)

    assert provider.pull_tick_input(0) == []


def test_replay_provider_uses_eos_exception_not_stall_none() -> None:
    provider = ReplayInputProvider(
        player_count=1,
        resolve_tick_input=lambda tick_index: [PlayerInput()] if int(tick_index) == 0 else None,
        tick_count=1,
    )
    provider.begin_frame(_FRAME_CTX)

    tick0 = provider.pull_tick_input(0)
    assert tick0 is not None

    with pytest.raises(ReplayEndOfStream):
        provider.pull_tick_input(1)


def test_replay_provider_resolves_inputs_lazily_per_tick() -> None:
    resolved_ticks: list[int] = []

    def _resolve_tick_input(tick_index: int) -> list[PlayerInput] | None:
        resolved_ticks.append(int(tick_index))
        if int(tick_index) > 1:
            return None
        return [PlayerInput()]

    provider = ReplayInputProvider(
        player_count=1,
        resolve_tick_input=_resolve_tick_input,
        tick_count=2,
    )
    provider.begin_frame(_FRAME_CTX)
    assert resolved_ticks == []

    tick0 = provider.pull_tick_input(0)
    tick1 = provider.pull_tick_input(1)
    assert tick0 is not None
    assert tick1 is not None
    assert resolved_ticks == [0, 1]

    with pytest.raises(ReplayEndOfStream):
        provider.pull_tick_input(2)
    assert resolved_ticks == [0, 1]


def test_network_provider_allows_stall_none_and_rejects_empty_nonzero() -> None:
    rows: dict[int, list[PlayerInput] | None] = {
        0: None,
        1: [],
    }
    provider = NetworkInputProvider(player_count=1, resolve_tick_input=lambda tick: rows.get(tick))
    provider.begin_frame(_FRAME_CTX)

    assert provider.pull_tick_input(0) is None
    with pytest.raises(ValueError, match="empty input list"):
        provider.pull_tick_input(1)
