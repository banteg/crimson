from __future__ import annotations

from dataclasses import dataclass, field
from unittest.mock import call

import pytest

import crimson.replay.driver.playback_pump as playback_pump_module
from crimson.replay.driver.playback_pump import advance_playback_frame
from crimson.sim.clock import FixedStepClock
from crimson.sim.presentation_step import DeterministicPresentationPlan
from crimson.sim.world_state import WorldEvents
from tests.support.builders import FakePlaybackDriver


@dataclass
class _SimWorldStub:
    calls: list[tuple[float, bool]] = field(default_factory=list)

    def apply_step_metadata(
        self,
        *,
        events: WorldEvents,
        presentation: DeterministicPresentationPlan,
        dt_sim: float,
        game_tune_started: bool,
    ) -> None:
        _ = events, presentation
        self.calls.append((float(dt_sim), bool(game_tune_started)))


def test_advance_playback_frame_increments_frame_and_tick_indices() -> None:
    clock = FixedStepClock(tick_rate=60)
    sim_world = _SimWorldStub()

    advance = advance_playback_frame(
        driver=FakePlaybackDriver(tick_limit=16),
        sim_world=sim_world,
        clock=clock,
        start_tick=4,
        frame_index=7,
        dt_seconds=2.0 * float(clock.dt_tick),
        max_ticks=None,
        tick_limit=16,
        game_tune_started=False,
    )

    assert advance.frame_index == 8
    assert advance.next_tick_index == 6
    assert advance.ticks_requested == 2
    assert advance.ticks_completed == 2
    assert len(sim_world.calls) == 2


def test_advance_playback_frame_respects_max_ticks_clamp() -> None:
    clock = FixedStepClock(tick_rate=60)

    advance = advance_playback_frame(
        driver=FakePlaybackDriver(tick_limit=16),
        sim_world=_SimWorldStub(),
        clock=clock,
        start_tick=0,
        frame_index=0,
        dt_seconds=3.0 * float(clock.dt_tick),
        max_ticks=1,
        tick_limit=16,
        game_tune_started=False,
    )

    assert advance.ticks_requested == 1
    assert advance.ticks_completed == 1
    assert advance.next_tick_index == 1


def test_advance_playback_frame_keeps_output_and_outcome_order() -> None:
    clock = FixedStepClock(tick_rate=60)

    advance = advance_playback_frame(
        driver=FakePlaybackDriver(tick_limit=16),
        sim_world=_SimWorldStub(),
        clock=clock,
        start_tick=5,
        frame_index=0,
        dt_seconds=3.0 * float(clock.dt_tick),
        max_ticks=None,
        tick_limit=16,
        game_tune_started=False,
    )

    assert [int(output.tick_index) for output in advance.outputs] == [5, 6, 7]
    assert [int(tick_result.source_tick.tick_index) for tick_result in advance.tick_results] == [5, 6, 7]


def test_advance_playback_frame_refunds_unconsumed_ticks_when_tick_limit_truncates() -> None:
    clock = FixedStepClock(tick_rate=60)

    advance = advance_playback_frame(
        driver=FakePlaybackDriver(tick_limit=2),
        sim_world=_SimWorldStub(),
        clock=clock,
        start_tick=1,
        frame_index=0,
        dt_seconds=3.0 * float(clock.dt_tick),
        max_ticks=None,
        tick_limit=2,
        game_tune_started=False,
    )

    assert advance.ticks_requested == 3
    assert advance.ticks_completed == 1
    assert advance.next_tick_index == 2
    assert clock.accum == pytest.approx(2.0 * float(clock.dt_tick))


def test_advance_playback_frame_does_not_refund_when_all_ticks_complete() -> None:
    clock = FixedStepClock(tick_rate=60)

    advance = advance_playback_frame(
        driver=FakePlaybackDriver(tick_limit=16),
        sim_world=_SimWorldStub(),
        clock=clock,
        start_tick=0,
        frame_index=0,
        dt_seconds=2.0 * float(clock.dt_tick),
        max_ticks=None,
        tick_limit=16,
        game_tune_started=False,
    )

    assert advance.ticks_completed == 2
    assert clock.accum == pytest.approx(0.0)


def test_advance_playback_frame_applies_sim_metadata_after_shared_batch_step_order(mocker) -> None:
    sequence = mocker.Mock()
    clock = FixedStepClock(tick_rate=60)

    def _on_step() -> None:
        sequence.step()

    apply_tick_to_sim = mocker.patch.object(
        playback_pump_module,
        "apply_tick_to_sim",
        side_effect=lambda **_kwargs: sequence.apply(),
    )

    advance = advance_playback_frame(
        driver=FakePlaybackDriver(tick_limit=2, on_step=_on_step),
        sim_world=_SimWorldStub(),
        clock=clock,
        start_tick=0,
        frame_index=0,
        dt_seconds=2.0 * float(clock.dt_tick),
        max_ticks=None,
        tick_limit=2,
        game_tune_started=True,
    )

    assert advance.ticks_completed == 2
    assert sequence.mock_calls == [call.step(), call.step(), call.apply(), call.apply()]
    assert apply_tick_to_sim.call_count == 2
