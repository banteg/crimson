from __future__ import annotations

import msgspec
import pytest

from crimson.aim_schemes import AimScheme
from crimson.movement_controls import MovementControlType
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
from grim.geom import Vec2
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


def test_provider_returns_stalled_when_no_inputs() -> None:
    provider = StalledInputProvider()
    provider.begin_frame(_FRAME_CTX)

    tick0 = provider.pull_tick(0, _FRAME_CTX.tick_dt_seconds)
    assert tick0.status is InputStatus.STALLED
    assert tick0.tick is None


def test_provider_returns_resolved_tick_inline() -> None:
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
    assert batch.completed_results[0].payload.dt_sim == pytest.approx(1.0 / 30.0)


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


@pytest.mark.parametrize("move_mode", list(MovementControlType))
@pytest.mark.parametrize("aim_scheme", list(AimScheme))
def test_additional_ticks_preserve_control_modes_and_held_buttons(
    move_mode: MovementControlType,
    aim_scheme: AimScheme,
) -> None:
    original = PlayerInput(
        move_mode=move_mode,
        aim_scheme=aim_scheme,
        fire_down=True,
        fire_pressed=True,
        reload_down=True,
        reload_pressed=True,
        move_to_cursor_pressed=True,
        move_forward_pressed=True,
        move_backward_pressed=False,
        turn_left_pressed=True,
        turn_right_pressed=False,
    )
    provider = LocalInputProvider(player_count=1, runtime=StaticLocalInputRuntime(inputs=(original,)))
    provider.begin_frame(_FRAME_CTX)
    first = provider.pull_tick(0, 1 / 60).tick
    second = provider.pull_tick(1, 1 / 60).tick
    assert first is not None and second is not None
    assert first.inputs == (original,)
    assert second.inputs == (
        msgspec.structs.replace(
            original,
            fire_pressed=False,
            reload_pressed=False,
            move_to_cursor_pressed=False,
        ),
    )


@pytest.mark.parametrize("zero_tick_frames", [1, 3, 10])
def test_pending_edges_survive_until_a_tick_and_use_latest_held_state(zero_tick_frames: int) -> None:
    runtime = StaticLocalInputRuntime(inputs=(PlayerInput(fire_pressed=True, fire_down=True),))
    provider = LocalInputProvider(player_count=1, runtime=runtime)
    provider.submit_command(PerkMenuOpenCommand(player_index=0))
    for frame in range(zero_tick_frames):
        provider.begin_frame(msgspec.structs.replace(_FRAME_CTX, frame_index=frame, candidate_ticks=0))
        runtime.inputs = (PlayerInput(reload_pressed=True, aim=Vec2(123, 456)),)
    provider.begin_frame(_FRAME_CTX)
    first = provider.pull_tick(0, 1 / 60).tick
    second = provider.pull_tick(1, 1 / 60).tick
    assert first is not None and second is not None
    assert first.inputs == (PlayerInput(fire_pressed=True, reload_pressed=True, aim=Vec2(123, 456)),)
    assert first.commands == (PerkMenuOpenCommand(player_index=0),)
    assert second.inputs == (PlayerInput(aim=Vec2(123, 456)),)
    assert second.commands == ()


def test_pause_discards_pending_edges_but_keeps_commands_and_held_controls() -> None:
    provider = LocalInputProvider(
        player_count=1,
        runtime=StaticLocalInputRuntime(
            inputs=(PlayerInput(fire_pressed=True, fire_down=True, reload_pressed=True, reload_down=True),),
        ),
    )
    command = PerkMenuOpenCommand(player_index=0)
    provider.submit_command(command)
    provider.begin_frame(_FRAME_CTX)
    provider.clear_pending_edges()
    tick = provider.pull_tick(0, 1 / 60).tick
    assert tick is not None
    assert tick.inputs == (PlayerInput(fire_down=True, reload_down=True),)
    assert tick.commands == (command,)
