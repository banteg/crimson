from __future__ import annotations

from pathlib import Path

import pytest

from crimson.dbg.checkpoint_diff import compare_checkpoints
from crimson.replay import load_replay_file
from crimson.replay.checkpoints import load_checkpoints_file
from crimson.sim.driver.replay_runner import run_replay

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "replays"

pytestmark = [pytest.mark.slow, pytest.mark.replay_fixture]

_REPLAY_CASES = (
    # This sidecar was recorded before the TickRunner checkpoint-order fix
    # (checkpoint hook fired before world apply). Keep the known divergence
    # pinned until fixtures are refreshed from a fixed build.
    (
        "survival_20260303_213138_score164406.crd",
        45337,
        164406,
        1895,
        "state_mismatch",
        2520,
    ),
    ("rush_20260303_211707_kills136.crd", 2041, 21771, 136, None, None),
    ("quest_1.5_20260303_211620_completed_t40512.crd", 2685, 23818, 19, None, None),
)


@pytest.mark.parametrize(
    (
        "replay_name",
        "expected_ticks",
        "expected_score_xp",
        "expected_kills",
        "expected_diff_kind",
        "expected_diff_tick",
    ),
    _REPLAY_CASES,
)
def test_replay_fixture_run_stats_and_checkpoint_parity(
    replay_name: str,
    expected_ticks: int,
    expected_score_xp: int,
    expected_kills: int,
    expected_diff_kind: str | None,
    expected_diff_tick: int | None,
) -> None:
    replay_path = FIXTURE_DIR / replay_name
    checkpoints_path = replay_path.with_name(f"{replay_path.name}.chk")

    if not replay_path.is_file() or not checkpoints_path.is_file():
        pytest.skip(f"missing replay fixture: {replay_name}")

    replay = load_replay_file(replay_path)
    expected_sidecar = load_checkpoints_file(checkpoints_path)

    actual_checkpoints = []
    checkpoint_ticks = {int(ckpt.tick_index) for ckpt in expected_sidecar.checkpoints}
    run_result = run_replay(
        replay,
        checkpoints_out=actual_checkpoints,
        checkpoint_ticks=checkpoint_ticks,
    )
    diff = compare_checkpoints(expected_sidecar.checkpoints, actual_checkpoints)

    assert run_result.ticks == int(expected_ticks)
    assert run_result.score_xp == int(expected_score_xp)
    assert run_result.creature_kill_count == int(expected_kills)
    if expected_diff_kind is None:
        assert diff.ok
        return
    assert expected_diff_tick is not None
    assert not diff.ok
    assert diff.failure is not None
    assert diff.failure.kind == str(expected_diff_kind)
    assert diff.failure.tick_index == int(expected_diff_tick)
