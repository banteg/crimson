"""Record current-rule fixture results and checkpoints from generated inputs.

Run matrix.mjs and service/scripts/vectors.py first. Historical recordings are
never relabelled. These are generated inputs, not human gameplay recordings.
"""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path

import msgspec
from gate import Stream

from crimson.game_version import REPLAY_RULES, current_replay_game_version
from crimson.replay.checkpoints import FORMAT_VERSION, ReplayCheckpoints, dump_checkpoints_file
from crimson.replay.codec import dump_replay_file, load_replay
from crimson.replay.driver.playback_driver import PlaybackDriver
from crimson.replay.types import current_recorder

ROOT = Path(__file__).resolve().parents[2]
DEST = ROOT / "tests/fixtures/replays"
SOURCES = {
    "coop-perk-timers-rules2": "coop-survival-independent-timers-ranked",
    "quest-1.1-rules2": "quest-1.1-ranked",
    "rush-rules2": "rush-bot-ranked",
    "survival-rules2": "survival-bot-ranked",
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEST)
    output = parser.parse_args().output
    output.mkdir(parents=True, exist_ok=True)
    assert REPLAY_RULES == 2, "Choose new fixture names for the next rules version"
    vectors = json.loads((ROOT / "service/test/vectors.json").read_text())
    replays = {
        name: msgspec.structs.replace(load_replay(base64.b64decode(payload)), seat_keys=None)
        for name, payload in (
            ("rules2-survival", vectors["ranked_run"]),
            ("rules2-survival-coop", vectors["coop_run"]["file"]),
        )
    }
    for name, source in SOURCES.items():
        path = ROOT / f"crimson-core/build/fixtures/{source}.rsi"
        replays[name] = Stream(source, path.read_bytes()).replay()
    for name, replay in replays.items():
        replay = msgspec.structs.replace(
            replay, game_version=current_replay_game_version(), recorder=current_recorder(),
        )
        driver = PlaybackDriver(replay, warn_on_version_mismatch=False)
        checkpoints = [driver.build_checkpoint(tick_result=driver.step_tick(i)) for i in range(len(replay.ticks))]
        result = driver.build_result()
        if name not in SOURCES:
            assert result == replay.result, (name, result, replay.result)
        path = output / f"{name}.crd"
        dump_replay_file(path, msgspec.structs.replace(replay, result=result))
        dump_checkpoints_file(
            path.with_suffix(".crd.chk"),
            ReplayCheckpoints(version=FORMAT_VERSION, sample_rate=1, checkpoints=checkpoints),
        )
        print(name, len(replay.ticks), result, flush=True)


if __name__ == "__main__":
    main()
