from __future__ import annotations

import pytest

from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import (
    FrameContext,
    InputStatus,
    LocalInputProvider,
    NetworkInputProvider,
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
        build_inputs=lambda _frame_ctx: [PlayerInput(fire_down=True, fire_pressed=True)],
    )
    provider.begin_frame(_FRAME_CTX)

    first = provider.pull_tick_input(0)
    second = provider.pull_tick_input(1)

    assert first.status is InputStatus.READY
    assert second.status is InputStatus.READY
    assert first.inputs[0].fire_pressed is True
    assert second.inputs[0].fire_pressed is False


def test_local_provider_rejects_empty_inputs_when_players_exist() -> None:
    provider = LocalInputProvider(player_count=1, build_inputs=lambda _frame_ctx: [])

    with pytest.raises(ValueError, match="empty input list"):
        provider.begin_frame(_FRAME_CTX)


def test_local_provider_allows_empty_inputs_for_zero_players() -> None:
    provider = LocalInputProvider(player_count=0, build_inputs=lambda _frame_ctx: [])
    provider.begin_frame(_FRAME_CTX)

    tick0 = provider.pull_tick_input(0)
    assert tick0.status is InputStatus.READY
    assert tick0.inputs == []


def test_replay_provider_uses_eos_status_not_stall() -> None:
    provider = ReplayInputProvider(
        player_count=1,
        resolve_tick_input=lambda tick_index: [PlayerInput()] if int(tick_index) == 0 else None,
        tick_count=1,
    )
    provider.begin_frame(_FRAME_CTX)

    tick0 = provider.pull_tick_input(0)
    assert tick0.status is InputStatus.READY
    assert provider.pull_tick_input(1).status is InputStatus.EOS


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
    assert tick0.status is InputStatus.READY
    assert tick1.status is InputStatus.READY
    assert resolved_ticks == [0, 1]

    assert provider.pull_tick_input(2).status is InputStatus.EOS
    assert resolved_ticks == [0, 1]


def test_network_provider_returns_stalled_and_rejects_empty_nonzero() -> None:
    rows: dict[int, list[PlayerInput] | None] = {
        0: None,
        1: [],
    }
    provider = NetworkInputProvider(player_count=1, resolve_tick_input=lambda tick: rows.get(tick))
    provider.begin_frame(_FRAME_CTX)

    tick0 = provider.pull_tick_input(0)
    assert tick0.status is InputStatus.STALLED
    assert tick0.inputs == []
    with pytest.raises(ValueError, match="empty input list"):
        provider.pull_tick_input(1)


def test_replay_provider_can_read_from_journal_api() -> None:
    class _FakeJournal:
        def __init__(self) -> None:
            self.read_calls: list[int] = []
            self.dt_calls: list[int] = []

        def tick_count(self) -> int:
            return 2

        def read_tick_inputs(self, tick_index: int) -> list[PlayerInput] | None:
            self.read_calls.append(int(tick_index))
            if int(tick_index) >= 2:
                return None
            return [PlayerInput()]

        def read_tick_dt(self, tick_index: int, default_dt: float) -> float:
            _ = default_dt
            self.dt_calls.append(int(tick_index))
            return 1.0 / 120.0

    journal = _FakeJournal()
    provider = ReplayInputProvider(
        player_count=1,
        journal=journal,
    )
    provider.begin_frame(_FRAME_CTX)

    tick0 = provider.pull_tick_input(0)
    tick1 = provider.pull_tick_input(1)
    tick2 = provider.pull_tick_input(2)

    assert tick0.status is InputStatus.READY
    assert tick1.status is InputStatus.READY
    assert tick2.status is InputStatus.EOS
    assert journal.read_calls == [0, 1]
    assert provider.resolve_tick_dt(0, 1.0 / 60.0) == pytest.approx(1.0 / 120.0)
    assert journal.dt_calls == [0]
