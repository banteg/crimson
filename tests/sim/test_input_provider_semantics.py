from __future__ import annotations

import pytest

from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import (
    FrameContext,
    GameCommand,
    InputProvider,
    InputStatus,
    LocalInputProvider,
    PerkMenuOpenCommand,
    ResolvedTick,
    TickSupply,
)
from crimson.sim.tick_runner import TickRunner, TickRunnerConfig
from tests.support.builders.input_providers import (
    ReadyTickInputProvider,
    StalledInputProvider,
    StaticLocalInputRuntime,
)
from tests.support.builders.session import make_session

_FRAME_CTX = FrameContext(
    dt_seconds=1.0 / 60.0,
    tick_dt_seconds=1.0 / 60.0,
    frame_index=1,
    candidate_ticks=1,
)


def test_local_provider_never_stalls_and_clears_edges() -> None:
    provider = LocalInputProvider(
        player_count=1,
        runtime=StaticLocalInputRuntime(inputs=(PlayerInput(fire_down=True, fire_pressed=True),)),
    )
    provider.begin_frame(_FRAME_CTX)

    first = provider.pull_tick(0, _FRAME_CTX.tick_dt_seconds)
    second = provider.pull_tick(1, _FRAME_CTX.tick_dt_seconds)

    assert first.status is InputStatus.READY
    assert second.status is InputStatus.READY
    assert first.tick is not None
    assert second.tick is not None
    assert first.tick.inputs[0].fire_pressed is True
    assert second.tick.inputs[0].fire_pressed is False


def test_local_provider_allows_empty_inputs_for_zero_players() -> None:
    provider = LocalInputProvider(player_count=0, runtime=StaticLocalInputRuntime())
    provider.begin_frame(_FRAME_CTX)

    tick0 = provider.pull_tick(0, _FRAME_CTX.tick_dt_seconds)
    assert tick0.status is InputStatus.READY
    assert tick0.tick is not None
    assert tick0.tick.inputs == ()


def test_network_provider_returns_stalled_when_no_inputs() -> None:
    provider = StalledInputProvider()
    provider.begin_frame(_FRAME_CTX)

    tick0 = provider.pull_tick(0, _FRAME_CTX.tick_dt_seconds)
    assert tick0.status is InputStatus.STALLED
    assert tick0.tick is None


def test_network_provider_returns_resolved_tick_inline() -> None:
    provider = ReadyTickInputProvider(inputs=(PlayerInput(),))
    provider.begin_frame(_FRAME_CTX)

    tick0 = provider.pull_tick(0, _FRAME_CTX.tick_dt_seconds)

    assert tick0.status is InputStatus.READY
    assert tick0.tick is not None
    assert tick0.tick.tick_index == 0
    assert tick0.tick.inputs == (PlayerInput(),)
    assert tick0.tick.commands == ()


def test_resolved_tick_schema_uses_tuple_inputs_and_commands() -> None:
    command = PerkMenuOpenCommand(player_index=0)
    tick = ResolvedTick(
        tick_index=3,
        dt_seconds=1.0 / 60.0,
        inputs=(PlayerInput(fire_down=True),),
        commands=(command,),
    )

    assert tick.tick_index == 3
    assert tick.inputs == (PlayerInput(fire_down=True),)
    assert tick.commands == (command,)


class _SingleSupplyProvider(InputProvider):
    def __init__(self, supply: TickSupply) -> None:
        self._supply = supply

    def begin_frame(self, frame_ctx: FrameContext) -> None:
        _ = frame_ctx

    def pull_tick(self, tick_index: int, default_dt_seconds: float) -> TickSupply:
        _ = tick_index, default_dt_seconds
        return self._supply

    def supports_command_submission(self) -> bool:
        return False

    def submit_command(self, command: GameCommand) -> None:
        _ = command


def test_runner_uses_resolved_tick_dt_instead_of_default_tick_dt() -> None:
    session, _ = make_session()
    provider = _SingleSupplyProvider(
        TickSupply(
            status=InputStatus.READY,
            tick=ResolvedTick(
                tick_index=0,
                dt_seconds=1.0 / 30.0,
                inputs=(PlayerInput(),),
                commands=(),
            ),
        ),
    )
    runner = TickRunner(session=session, input_provider=provider, config=TickRunnerConfig())

    batch = runner.advance_ticks(start_tick=0, ticks_requested=1, tick_dt=1.0 / 60.0)

    assert batch.ticks_completed == 1
    assert batch.completed_results[0].payload.step.dt_sim == pytest.approx(1.0 / 30.0)


def test_runner_rejects_ready_supply_without_resolved_tick() -> None:
    session, _ = make_session()
    provider = _SingleSupplyProvider(TickSupply(status=InputStatus.READY, tick=None))
    runner = TickRunner(session=session, input_provider=provider, config=TickRunnerConfig())

    with pytest.raises(RuntimeError, match="ready tick supply"):
        runner.advance_ticks(start_tick=0, ticks_requested=1, tick_dt=1.0 / 60.0)


@pytest.mark.parametrize("status", [InputStatus.STALLED, InputStatus.EOS])
def test_runner_rejects_non_ready_supply_with_resolved_tick(status: InputStatus) -> None:
    session, _ = make_session()
    provider = _SingleSupplyProvider(
        TickSupply(
            status=status,
            tick=ResolvedTick(
                tick_index=0,
                dt_seconds=1.0 / 60.0,
                inputs=(PlayerInput(),),
                commands=(),
            ),
        ),
    )
    runner = TickRunner(session=session, input_provider=provider, config=TickRunnerConfig())

    with pytest.raises(RuntimeError, match=f"{status.value} tick supply"):
        runner.advance_ticks(start_tick=0, ticks_requested=1, tick_dt=1.0 / 60.0)


def test_runner_rejects_mismatched_resolved_tick_index() -> None:
    session, _ = make_session()
    provider = _SingleSupplyProvider(
        TickSupply(
            status=InputStatus.READY,
            tick=ResolvedTick(
                tick_index=1,
                dt_seconds=1.0 / 60.0,
                inputs=(PlayerInput(),),
                commands=(),
            ),
        ),
    )
    runner = TickRunner(session=session, input_provider=provider, config=TickRunnerConfig())

    with pytest.raises(RuntimeError, match="resolved tick index mismatch"):
        runner.advance_ticks(start_tick=0, ticks_requested=1, tick_dt=1.0 / 60.0)
