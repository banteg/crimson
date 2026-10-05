from __future__ import annotations

import msgspec
import pytest

from crimson.aim_schemes import AimScheme
from crimson.movement_controls import MovementControlType
from crimson.perks import PerkId
from crimson.replay.checkpoints import ReplayCheckpoint, build_checkpoint
from crimson.replay.input_codec import unpack_player_input
from crimson.replay.rng_call_order import RngCallOrder
from crimson.replay.ticks import LiveTickSource, step_replay_tick
from crimson.sim.clock import FixedStepClock
from crimson.sim.input import PlayerInput
from crimson.sim.presentation_step import DeterministicPresentationPlan
from grim.geom import Vec2
from tests.support.builders.session import make_session


def _run_render_partition(render_hz: int) -> list[tuple[ReplayCheckpoint, DeterministicPresentationPlan, PlayerInput]]:
    session, sim = make_session(seed=123)
    player = sim.players[0]
    sim.state.perks[int(PerkId.ANXIOUS_LOADER)] = 1
    player.weapon.reload_timer = 0.09
    player.weapon.reload_active = True
    player.weapon.ammo = 0.0
    controls = PlayerInput(
        move=Vec2(0, -1), aim=Vec2(700, 300),
        move_mode=MovementControlType.RELATIVE, aim_scheme=AimScheme.KEYBOARD,
        move_forward_down=True, move_backward_down=False, turn_left_down=True, turn_right_down=False,
        reload_down=True, fire_down=True, fire_pressed=True,
    )
    ticks = LiveTickSource()
    clock = FixedStepClock(tick_rate=60)
    rows = []
    rng_call_order = RngCallOrder()

    frame_input = controls
    for _ in range(render_hz // 15):
        ticks.poll([frame_input])
        for _ in range(clock.advance(1 / render_hz)):
            tick = ticks.next_tick()
            with rng_call_order.recording(session.world.state.rng):
                step = step_replay_tick(session, tick)
            rows.append((
                build_checkpoint(
                    tick_index=len(rows), world=session.world, elapsed_ms=session.elapsed_ms,
                    rng_callers_crc32=rng_call_order.crc32(), events=step.events, deaths=step.events.deaths,
                ),
                step.presentation,
                unpack_player_input(tick.inputs[0]),
            ))
        frame_input = msgspec.structs.replace(controls, fire_pressed=False)
    assert len(rows) == 4
    assert [row[2].fire_pressed for row in rows] == [True, False, False, False]
    return rows


@pytest.mark.parametrize("render_hz", [120, 30])
def test_render_partitions_preserve_every_checkpoint_input_and_presentation_request(render_hz: int) -> None:
    assert _run_render_partition(render_hz) == _run_render_partition(60)
