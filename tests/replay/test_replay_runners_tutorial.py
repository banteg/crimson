from __future__ import annotations

from tests.support.replay_runner_helpers import _blank_tutorial_replay, _run_verify_playback, finish_replay


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
