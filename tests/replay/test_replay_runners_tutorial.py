from __future__ import annotations

from crimson.replay.driver.playback_driver import build_verify_playback_driver
from crimson.sim.bootstrap import advance_unlock_terrain
from crimson.sim.run_result import RunOutcome
from crimson.sim.run_spec import WORLD_SIZE
from grim.rand import Crand
from tests.support.replay_runner_helpers import _blank_tutorial_replay, _run_verify_playback, finish_replay


def test_tutorial_runner_uses_header_seed_for_startup_terrain_prelude() -> None:
    rec = _blank_tutorial_replay(ticks=0, seed=0x1234)
    replay = finish_replay(rec)
    driver = build_verify_playback_driver(replay)

    rng = Crand(int(replay.run.seed))
    terrain = advance_unlock_terrain(
        rng,
        unlock_index=int(replay.run.status.quest_unlock_index),
        width=int(WORLD_SIZE),
        height=int(WORLD_SIZE),
    )

    terrain_setup = driver.terrain_setup
    assert terrain_setup is not None
    assert terrain_setup.terrain_slots == terrain.terrain_slots
    assert terrain_setup.terrain_seed == int(terrain.terrain_seed)
    assert int(driver.world.state.rng.state) == int(rng.state)


def test_tutorial_runner_checkpoints_capture_tutorial_state() -> None:
    rec = _blank_tutorial_replay(ticks=80, seed=0xBEEF)
    replay = finish_replay(rec)
    checkpoints = []

    _run_verify_playback(
        replay,
        checkpoints_out=checkpoints,
        checkpoint_ticks={70},
    )

    assert [int(ckpt.tick_index) for ckpt in checkpoints] == [70]
    assert checkpoints[0].tutorial is not None
    assert checkpoints[0].tutorial.prompt_text


def test_tutorial_runner_is_supported_in_shared_playback_pipeline() -> None:
    rec = _blank_tutorial_replay(ticks=5, seed=0xCAFE)
    replay = finish_replay(rec)

    result0 = _run_verify_playback(replay)
    result1 = _run_verify_playback(replay)

    assert result0 == result1 == replay.result
    assert result0.outcome == RunOutcome.INCOMPLETE
