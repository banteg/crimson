from __future__ import annotations

from pathlib import Path

import pytest

from crimson.replay.driver.playback_pump import advance_playback_frame
from crimson.sim.clock import FixedStepClock
from crimson.world import WorldRuntime
from grim.rand import Crand
from tests.support.builders import FakePlaybackDriver


def _runtime(assets_dir: Path) -> WorldRuntime:
    return WorldRuntime(assets_dir=assets_dir, audio_rng=Crand(0))


def test_advance_playback_frame_advances_tick_index(assets_dir: Path) -> None:
    clock = FixedStepClock(tick_rate=60)
    runtime = _runtime(assets_dir)

    advance = advance_playback_frame(
        driver=FakePlaybackDriver(tick_limit=16),
        runtime=runtime,
        clock=clock,
        start_tick=4,
        dt_seconds=2.0 * float(clock.dt_tick),
        max_ticks=None,
        tick_limit=16,
    )

    assert advance.next_tick_index == 6
    assert advance.ticks_requested == 2
    assert len(advance.tick_results) == 2
    assert runtime.presentation_elapsed_ms == pytest.approx(2.0 * 1000.0 / 60.0)


def test_advance_playback_frame_respects_max_ticks_clamp(assets_dir: Path) -> None:
    clock = FixedStepClock(tick_rate=60)

    advance = advance_playback_frame(
        driver=FakePlaybackDriver(tick_limit=16),
        runtime=_runtime(assets_dir),
        clock=clock,
        start_tick=0,
        dt_seconds=3.0 * float(clock.dt_tick),
        max_ticks=1,
        tick_limit=16,
    )

    assert advance.ticks_requested == 1
    assert len(advance.tick_results) == 1
    assert advance.next_tick_index == 1


def test_advance_playback_frame_refunds_unconsumed_ticks_when_tick_limit_truncates(assets_dir: Path) -> None:
    clock = FixedStepClock(tick_rate=60)

    advance = advance_playback_frame(
        driver=FakePlaybackDriver(tick_limit=2),
        runtime=_runtime(assets_dir),
        clock=clock,
        start_tick=1,
        dt_seconds=3.0 * float(clock.dt_tick),
        max_ticks=None,
        tick_limit=2,
    )

    assert advance.ticks_requested == 3
    assert len(advance.tick_results) == 1
    assert advance.next_tick_index == 2
    assert clock.accum == pytest.approx(2.0 * float(clock.dt_tick))


def test_advance_playback_frame_advances_presentation_clock_after_stepping_the_batch(assets_dir: Path) -> None:
    clock = FixedStepClock(tick_rate=60)
    runtime = _runtime(assets_dir)
    elapsed_at_step: list[float] = []

    advance = advance_playback_frame(
        driver=FakePlaybackDriver(
            tick_limit=2,
            on_step=lambda: elapsed_at_step.append(runtime.presentation_elapsed_ms),
        ),
        runtime=runtime,
        clock=clock,
        start_tick=0,
        dt_seconds=2.0 * float(clock.dt_tick),
        max_ticks=None,
        tick_limit=2,
    )

    assert len(advance.tick_results) == 2
    assert elapsed_at_step == [0.0, 0.0]
    assert runtime.presentation_elapsed_ms == pytest.approx(2.0 * 1000.0 / 60.0)
    assert runtime.bonus_anim_phase == pytest.approx(2.0 * 1.3 / 60.0)
