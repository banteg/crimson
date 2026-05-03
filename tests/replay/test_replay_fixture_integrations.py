from __future__ import annotations

from pathlib import Path

import pytest

from crimson.dbg.checkpoint_diff import compare_checkpoints
from crimson.replay import Replay, ReplayCodecError, load_replay_file
from crimson.replay.checkpoints import ReplayCheckpoint, load_checkpoints_file
from crimson.replay.driver.playback_driver import (
    PlaybackDriver,
    PlaybackWalkObserver,
    build_verify_playback_driver,
)
from crimson.sim.hooks import TickResult
from crimson.sim.world_state import WorldState
from tests.support.replay_runner_helpers import _run_verify_playback

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "replays"

pytestmark = [pytest.mark.slow, pytest.mark.replay_fixture]

_REPLAY_CASES = (
    ("survival_20260303_213138_score164406.crd", 45337, 164406, 1895),
    ("rush_20260303_211707_kills136.crd", 2041, 21771, 136),
    ("quest_1.5_20260303_211620_completed_t40512.crd", 2685, 23818, 19),
    ("quest_2.10_20260305_201829_completed_t51600.crd", 3378, 132062, 762),
)
_PLAYBACK_CHUNK_PATTERN = (1, 7, 31, 256)


def _sample_tick_indexes(total_ticks: int) -> set[int]:
    if total_ticks <= 0:
        return set()
    last_tick = int(total_ticks) - 1
    return {
        0,
        int(last_tick // 3),
        int((last_tick * 2) // 3),
        int(last_tick),
    }


def _build_verify_driver(*, replay):
    return build_verify_playback_driver(
        replay,
        trace_rng=False,
        warn_on_version_mismatch=True,
    )


def _load_replay_fixture_or_skip(replay_path: Path) -> Replay:
    try:
        return load_replay_file(replay_path)
    except ReplayCodecError as exc:
        pytest.skip(f"legacy replay fixture is not accepted by the current replay codec: {exc}")


class _CheckpointObserver(PlaybackWalkObserver):
    driver: PlaybackDriver
    checkpoint_ticks: set[int]
    checkpoints: list[ReplayCheckpoint]

    def after_tick(self, tick_result: TickResult, world: WorldState) -> None:
        _ = world
        if int(tick_result.source_tick.tick_index) in self.checkpoint_ticks:
            self.checkpoints.append(self.driver.build_checkpoint(tick_result=tick_result))


def _run_walk_playback(
    *,
    replay,
    checkpoint_ticks: set[int],
):
    driver = _build_verify_driver(replay=replay)
    playback_checkpoints = []
    tick_index = 0
    chunk_index = 0
    tick_limit = int(driver.tick_limit)

    while tick_index < tick_limit:
        chunk_size = int(_PLAYBACK_CHUNK_PATTERN[chunk_index % len(_PLAYBACK_CHUNK_PATTERN)])
        chunk_end = min(tick_limit, tick_index + chunk_size)

        walk_result = driver.walk_ticks(
            start_tick=tick_index,
            stop_tick=chunk_end,
            observer=_CheckpointObserver(
                driver=driver,
                checkpoint_ticks=checkpoint_ticks,
                checkpoints=playback_checkpoints,
            ),
        )
        tick_index = int(walk_result.next_tick_index)
        chunk_index += 1

    return driver.build_run_result(ticks=tick_index), playback_checkpoints


@pytest.mark.parametrize(
    ("replay_name", "expected_ticks", "expected_score_xp", "expected_kills"),
    _REPLAY_CASES,
)
def test_replay_fixture_run_stats_and_checkpoint_parity(
    replay_name: str,
    expected_ticks: int,
    expected_score_xp: int,
    expected_kills: int,
) -> None:
    replay_path = FIXTURE_DIR / replay_name
    checkpoints_path = replay_path.with_name(f"{replay_path.name}.chk")

    if not replay_path.is_file() or not checkpoints_path.is_file():
        pytest.skip(f"missing replay fixture: {replay_name}")

    replay = _load_replay_fixture_or_skip(replay_path)
    expected_sidecar = load_checkpoints_file(checkpoints_path)

    actual_checkpoints = []
    checkpoint_ticks = {int(ckpt.tick_index) for ckpt in expected_sidecar.checkpoints}
    run_result = _run_verify_playback(
        replay,
        checkpoints_out=actual_checkpoints,
        checkpoint_ticks=checkpoint_ticks,
    )
    diff = compare_checkpoints(expected_sidecar.checkpoints, actual_checkpoints)

    assert run_result.ticks == int(expected_ticks)
    assert run_result.score_xp == int(expected_score_xp)
    assert run_result.creature_kill_count == int(expected_kills)
    assert diff.ok


@pytest.mark.parametrize(
    ("replay_name", "expected_ticks", "expected_score_xp", "expected_kills"),
    _REPLAY_CASES,
)
def test_verify_vs_playback_parity(
    replay_name: str,
    expected_ticks: int,
    expected_score_xp: int,
    expected_kills: int,
) -> None:
    replay_path = FIXTURE_DIR / replay_name
    if not replay_path.is_file():
        pytest.skip(f"missing replay fixture: {replay_name}")

    replay = _load_replay_fixture_or_skip(replay_path)
    checkpoint_ticks = _sample_tick_indexes(len(replay.ticks))
    verify_checkpoints = []
    verify_result = _run_verify_playback(
        replay,
        checkpoints_out=verify_checkpoints,
        checkpoint_ticks=checkpoint_ticks,
    )
    playback_result, playback_checkpoints = _run_walk_playback(
        replay=replay,
        checkpoint_ticks=checkpoint_ticks,
    )
    checkpoint_diff = compare_checkpoints(verify_checkpoints, playback_checkpoints)

    assert verify_result.ticks == int(expected_ticks)
    assert verify_result.score_xp == int(expected_score_xp)
    assert verify_result.creature_kill_count == int(expected_kills)
    assert playback_result == verify_result
    assert checkpoint_diff.ok
