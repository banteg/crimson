from __future__ import annotations

from crimson.replay.driver.playback_driver import build_verify_playback_driver
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.bootstrap import advance_gameplay_reset_rng
from crimson.sim.terrain_generate import terrain_generate_random
from grim.rand import Crand
from tests.support.replay_runner_helpers import _blank_tutorial_replay, _run_verify_playback, finish_replay


def test_tutorial_runner_uses_header_seed_for_startup_terrain_prelude() -> None:
    rec = _blank_tutorial_replay(ticks=0, seed=0x1234)
    replay = finish_replay(rec)
    driver = build_verify_playback_driver(replay)

    rng = Crand(int(replay.run.seed))
    advance_gameplay_reset_rng(rng)
    terrain = terrain_generate_random(rng, int(replay.run.status.quest_unlock_index))
    rng.rand_tagged(RngCallerStatic.GAME_FRAME_UPDATE_DISCARDED)

    terrain_setup = driver.terrain_setup
    assert terrain_setup is not None
    assert terrain_setup == terrain
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
