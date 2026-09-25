"""Generate a synthetic survival replay with kills for zig/python differential checks."""

from __future__ import annotations

import math
import sys
from pathlib import Path

from crimson.game_modes import GameMode
from crimson.replay import REPLAY_TICK_DT, ReplayRecorder, dump_replay_file
from crimson.sim.input import PlayerInput
from crimson.sim.run_init import initialize_run
from crimson.sim.run_result import build_run_result
from crimson.sim.run_spec import RunSpec
from grim.geom import Vec2


def main() -> None:
    out_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("artifacts/tests/kill_replay.crd")
    max_ticks = int(sys.argv[2]) if len(sys.argv) > 2 else 3000
    run = RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0xBEEF)
    session = initialize_run(run).session
    recorder = ReplayRecorder(run)
    # Record like live play: stop on the tick that ends the run.
    outcome = None
    for tick in range(max_ticks):
        angle = float(tick) * 0.05
        aim = Vec2(512.0 + math.cos(angle) * 200.0, 512.0 + math.sin(angle) * 200.0)
        inputs = [PlayerInput(aim=aim, fire_down=True, fire_pressed=tick % 30 == 0)]
        recorder.record_tick(inputs)
        outcome = session.step_tick(dt=REPLAY_TICK_DT, inputs=inputs).outcome
        if outcome is not None:
            break
    result = build_run_result(session, outcome=outcome or session.end_outcome())
    replay = recorder.finish(result)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    dump_replay_file(out_path, replay)
    print(
        f"wrote {out_path} ticks={len(replay.ticks)} outcome={result.outcome} kills={result.kills} "
        f"score={result.players[0].experience} rng_state={result.rng_state}",
    )


if __name__ == "__main__":
    main()
