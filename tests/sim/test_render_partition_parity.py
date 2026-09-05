from __future__ import annotations

import msgspec
import pytest

from crimson.aim_schemes import AimScheme
from crimson.movement_controls import MovementControlType
from crimson.perks import PerkId
from crimson.replay.checkpoints import ReplayCheckpoint, build_checkpoint
from crimson.sim.clock import FixedStepClock
from crimson.sim.frame_pump import advance_tick_runner_frame
from crimson.sim.hooks import TickResult
from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import LocalInputProvider
from crimson.sim.presentation_step import DeterministicPresentationPlan
from crimson.sim.tick_runner import TickRunner
from grim.geom import Vec2
from tests.support.builders.input_providers import StaticLocalInputRuntime
from tests.support.builders.session import make_session


def _run_render_partition(render_hz: int) -> list[tuple[ReplayCheckpoint, DeterministicPresentationPlan, PlayerInput]]:
    session, sim = make_session(seed=123)
    player = sim.players[0]
    player.perk_counts[int(PerkId.ANXIOUS_LOADER)] = 1
    player.weapon.reload_timer = 0.09
    player.weapon.reload_active = True
    player.weapon.ammo = 0.0
    controls = PlayerInput(
        move=Vec2(0, -1), aim=Vec2(700, 300),
        move_mode=MovementControlType.RELATIVE, aim_scheme=AimScheme.KEYBOARD,
        move_forward_pressed=True, turn_left_pressed=True,
        reload_down=True, fire_down=True, fire_pressed=True,
    )
    input_runtime = StaticLocalInputRuntime(inputs=(controls,))
    provider = LocalInputProvider(player_count=1, runtime=input_runtime)
    runner = TickRunner(session=session, input_provider=provider)
    clock = FixedStepClock(tick_rate=60)
    rows = []

    def capture_current_tick(tick: TickResult) -> None:
        rows.append((
            build_checkpoint(
                tick_index=tick.source_tick.tick_index, world=session.world,
                elapsed_ms=session.elapsed_ms, events=tick.payload.events, deaths=tick.payload.events.deaths,
            ),
            tick.payload.presentation,
            tick.source_tick.inputs[0],
        ))

    tick_index = 0
    for frame in range(render_hz // 15):
        candidate_ticks = clock.advance(1 / render_hz)
        advance = advance_tick_runner_frame(
            runner=runner, start_tick=tick_index, frame_index=frame,
            ticks_requested=candidate_ticks, dt_seconds=1 / render_hz,
            tick_dt_seconds=clock.dt_tick, is_replay=False, refund_clock=clock,
            after_tick=capture_current_tick,
        )
        tick_index = advance.next_tick_index
        input_runtime.inputs = (msgspec.structs.replace(controls, fire_pressed=False),)
    assert tick_index == 4
    assert [row[2].fire_pressed for row in rows] == [True, False, False, False]
    return rows


@pytest.mark.parametrize("render_hz", [120, 30])
def test_render_partitions_preserve_every_checkpoint_input_and_presentation_request(render_hz: int) -> None:
    assert _run_render_partition(render_hz) == _run_render_partition(60)
