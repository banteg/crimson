"""Generate a synthetic survival replay with kills for zig/python differential checks."""

from __future__ import annotations

import math
import sys
from pathlib import Path

import msgspec

from crimson.game_modes import GameMode
from crimson.replay import ReplayHeader, ReplayRecorder, dump_replay
from crimson.replay.types import ReplayClaimedStatsSnapshot
from crimson.sim.input import PlayerInput
from grim.geom import Vec2


def main() -> None:
    out_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("artifacts/tests/kill_replay.crd")
    ticks = int(sys.argv[2]) if len(sys.argv) > 2 else 3000
    header = ReplayHeader(
        game_mode_id=GameMode.SURVIVAL,
        seed=0xBEEF,
        tick_rate=60,
        player_count=1,
    )
    recorder = ReplayRecorder(header)
    for tick in range(ticks):
        angle = float(tick) * 0.05
        aim = Vec2(512.0 + math.cos(angle) * 200.0, 512.0 + math.sin(angle) * 200.0)
        recorder.record_tick([PlayerInput(aim=aim, fire_down=True, fire_pressed=tick % 30 == 0)])
    replay = recorder.finish()

    from crimson.replay.driver.playback_driver import build_verify_playback_driver

    driver = build_verify_playback_driver(replay, warn_on_version_mismatch=False)
    driver.walk_ticks(start_tick=0, stop_tick=int(driver.tick_limit))
    result = driver.build_run_result(ticks=int(driver.tick_limit))
    replay = msgspec.structs.replace(
        replay,
        header=msgspec.structs.replace(
            replay.header,
            claimed_stats=ReplayClaimedStatsSnapshot(
                complete=True,
                ticks=result.ticks,
                elapsed_ms=result.elapsed_ms,
                score_xp=result.score_xp,
                kills=result.creature_kill_count,
                most_used_weapon_id=result.most_used_weapon_id,
                shots_fired=result.shots_fired,
                shots_hit=result.shots_hit,
            ),
        ),
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(dump_replay(replay))
    print(f"wrote {out_path} ticks={result.ticks} kills={result.creature_kill_count} score={result.score_xp} rng_state={result.rng_state}")


if __name__ == "__main__":
    main()
