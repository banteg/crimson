from __future__ import annotations

import pytest

from crimson.replay.driver.playback_driver import (
    PlaybackWalkHooks,
    PlaybackWalkResult,
    build_verify_playback_driver,
)
from crimson.replay.driver.setup import ReplayRunnerError
from tests.support.replay_runner_helpers import _blank_survival_replay


def test_playback_driver_walk_before_and_after_hooks_see_pre_and_post_step_world(mocker) -> None:
    _header, rec = _blank_survival_replay(ticks=1, seed=0x1234)
    replay = rec.finish()
    driver = build_verify_playback_driver(replay)
    observed_before: list[int] = []
    observed_after: list[int] = []

    real_step_tick = driver.step_tick

    def _step_tick_with_mutation(tick_index: int):
        driver.world.players[0].experience = 99
        return real_step_tick(tick_index)

    mocker.patch.object(driver, "step_tick", side_effect=_step_tick_with_mutation)

    walk_result = driver.walk_ticks(
        hooks=PlaybackWalkHooks(
            before_tick=lambda _tick_index, world, _dt_tick: observed_before.append(int(world.players[0].experience)),
            after_tick=lambda _tick_result, world: observed_after.append(int(world.players[0].experience)),
        ),
    )

    assert walk_result == PlaybackWalkResult(start_tick=0, next_tick_index=1, ticks_completed=1)
    assert observed_before == [0]
    assert observed_after == [99]


def test_playback_driver_walk_progress_uses_absolute_completed_tick_indexes() -> None:
    _header, rec = _blank_survival_replay(ticks=4, seed=0x1234)
    replay = rec.finish()
    driver = build_verify_playback_driver(replay)
    progress_ticks: list[int] = []

    walk_result = driver.walk_ticks(
        start_tick=1,
        stop_tick=3,
        hooks=PlaybackWalkHooks(on_progress=progress_ticks.append),
    )

    assert walk_result == PlaybackWalkResult(start_tick=1, next_tick_index=3, ticks_completed=2)
    assert progress_ticks == [2, 3]


def test_playback_driver_walk_clamps_ranges_to_tick_limit() -> None:
    _header, rec = _blank_survival_replay(ticks=3, seed=0x1234)
    replay = rec.finish()
    driver = build_verify_playback_driver(replay)
    walked_ticks: list[int] = []

    walk_result = driver.walk_ticks(
        start_tick=2,
        stop_tick=10,
        hooks=PlaybackWalkHooks(
            after_tick=lambda tick_result, _world: walked_ticks.append(int(tick_result.source_tick.tick_index)),
        ),
    )

    assert walk_result == PlaybackWalkResult(start_tick=2, next_tick_index=3, ticks_completed=1)
    assert walked_ticks == [2]

    empty_driver = build_verify_playback_driver(replay)
    empty_result = empty_driver.walk_ticks(start_tick=10, stop_tick=12)
    assert empty_result == PlaybackWalkResult(start_tick=3, next_tick_index=3, ticks_completed=0)


def test_playback_driver_walk_rejects_invalid_ranges() -> None:
    _header, rec = _blank_survival_replay(ticks=3, seed=0x1234)
    replay = rec.finish()
    driver = build_verify_playback_driver(replay)

    with pytest.raises(ReplayRunnerError, match="invalid start_tick"):
        driver.walk_ticks(start_tick=-1)

    with pytest.raises(ReplayRunnerError, match="invalid tick range"):
        driver.walk_ticks(start_tick=2, stop_tick=1)


def test_playback_driver_walk_chunking_matches_full_run_result() -> None:
    _header, rec = _blank_survival_replay(ticks=5, seed=0x1234)
    replay = rec.finish()

    full_driver = build_verify_playback_driver(replay)
    full_walk = full_driver.walk_ticks()
    full_result = full_driver.build_run_result(ticks=full_walk.ticks_completed)

    chunked_driver = build_verify_playback_driver(replay)
    chunk0 = chunked_driver.walk_ticks(start_tick=0, stop_tick=2)
    chunk1 = chunked_driver.walk_ticks(start_tick=chunk0.next_tick_index, stop_tick=4)
    chunk2 = chunked_driver.walk_ticks(start_tick=chunk1.next_tick_index, stop_tick=10)
    chunked_result = chunked_driver.build_run_result(
        ticks=chunk0.ticks_completed + chunk1.ticks_completed + chunk2.ticks_completed,
    )

    assert chunk2 == PlaybackWalkResult(start_tick=4, next_tick_index=5, ticks_completed=1)
    assert chunked_result == full_result
