from __future__ import annotations

from crimson.replay import load_replay
from crimson.replay.saver import ReplaySaveJob, ReplaySaver
from tests.support.replay_runner_helpers import RECORDED_REPLAYS


def test_runs_ending_in_the_same_second_save_side_by_side(tmp_path) -> None:
    replay = load_replay(min(RECORDED_REPLAYS, key=lambda path: path.stat().st_size).read_bytes())
    saver = ReplaySaver()
    for _ in range(2):
        saver.submit(ReplaySaveJob(replay_dir=tmp_path, base_name="survival_20261006_120000", replay=replay))

    lines = saver.close()

    saved = [tmp_path / "survival_20261006_120000.crd", tmp_path / "survival_20261006_120000_1.crd"]
    assert lines == [f"replay: saved {path}" for path in saved]
    assert all(load_replay(path.read_bytes()) == replay for path in saved)
