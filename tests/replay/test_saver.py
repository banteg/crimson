from __future__ import annotations

import msgspec

from crimson.game_modes import GameMode
from crimson.replay import REPLAY_FORMAT_VERSION, load_replay
from crimson.replay.library import numbered_replay, replay_file_name
from crimson.replay.saver import ReplaySaveJob, ReplaySaver
from tests.support.replay_runner_helpers import RECORDED_REPLAYS


def test_runs_ending_together_get_the_next_numbers_and_their_files(tmp_path) -> None:
    # A recorded fixture, as the saver writes it: in the current format.
    recorded = load_replay(min(RECORDED_REPLAYS, key=lambda path: path.stat().st_size).read_bytes())
    replay = msgspec.structs.replace(recorded, format_version=REPLAY_FORMAT_VERSION)
    (tmp_path / "7-rush.crd").write_bytes(b"")
    saver = ReplaySaver()

    # The second number is handed out before the first replay is written.
    numbers = [saver.allocate(tmp_path) for _ in range(2)]
    for number in numbers:
        saver.submit(ReplaySaveJob(path=tmp_path / replay_file_name(number, GameMode.SURVIVAL), replay=replay))
    lines = saver.close()

    assert numbers == [8, 9]
    saved = [numbered_replay(tmp_path, number) for number in numbers]
    assert saved == [tmp_path / "8-survival.crd", tmp_path / "9-survival.crd"]
    assert lines == [f"replay: saved {path}" for path in saved]
    assert all(load_replay(path.read_bytes()) == replay for path in saved if path is not None)
    assert numbered_replay(tmp_path, 10) is None
