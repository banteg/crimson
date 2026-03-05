"""Regenerate .chk checkpoint sidecars for replay fixtures."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

from crimson.replay import load_replay_file
from crimson.replay.checkpoints import (
    FORMAT_VERSION,
    ReplayCheckpoints,
    dump_checkpoints_file,
)
from crimson.sim.driver.playback_driver import PlaybackDriver, PlaybackDriverOptions


def main() -> None:
    fixture_dir = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "replays"
    crd_files = sorted(fixture_dir.glob("*.crd"))
    if not crd_files:
        print("No .crd files found in", fixture_dir)
        sys.exit(1)

    for crd_path in crd_files:
        chk_path = crd_path.with_name(f"{crd_path.name}.chk")
        print(f"Regenerating {chk_path.name} from {crd_path.name} ...")

        crd_bytes = crd_path.read_bytes()
        replay_sha256 = hashlib.sha256(crd_bytes).hexdigest()
        replay = load_replay_file(crd_path)
        driver = PlaybackDriver(replay, PlaybackDriverOptions())
        checkpoints = []
        all_ticks = set(range(len(replay.ticks)))
        driver.run_to_completion(
            checkpoints_out=checkpoints,
            checkpoint_ticks=all_ticks,
        )

        payload = ReplayCheckpoints(
            version=int(FORMAT_VERSION),
            replay_sha256=str(replay_sha256),
            sample_rate=1,
            checkpoints=list(checkpoints),
        )
        dump_checkpoints_file(chk_path, payload)
        print(f"  -> wrote {len(checkpoints)} checkpoints to {chk_path.name}")


if __name__ == "__main__":
    main()
