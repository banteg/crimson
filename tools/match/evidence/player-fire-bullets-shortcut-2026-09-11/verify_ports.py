"""Verify G-key policy through CRD recording and complete Python/Zig replay ticks."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

import msgspec

from crimson.dbg.diff import diff_report_to_json, diff_traces
from crimson.dbg.record import record_replay_to_trace
from crimson.dbg.trace import iter_trace_ticks
from crimson.game_modes import GameMode
from crimson.movement_controls import MovementControlType
from crimson.replay import ReplayClaimedStatsSnapshot, ReplayHeader, ReplayRecorder, dump_replay
from crimson.replay.driver.playback_driver import build_verify_playback_driver
from crimson.sim.input import PlayerInput
from crimson.weapons import WeaponId
from grim.geom import Vec2

ROOT = Path(__file__).resolve().parents[4]
SOURCES = (
    "src/crimson/weapon_runtime/fire.py", "src/crimson/local_input.py", "src/crimson/sim/input.py",
    "src/crimson/replay/input_codec.py", "src/crimson/replay/types.py",
    "crimson-zig/src/local_input.zig", "crimson-zig/src/replay_codec.zig",
    "crimson-zig/src/runtime/player.zig", "crimson-zig/src/runtime/weapons.zig",
    "crimson-zig/src/runtime/replay_runner.zig", "crimson-zig/src/runtime/replay/step.zig",
    "scripts/frida/gameplay_diff_capture.js",
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--zig", type=Path, default=ROOT / "crimson-zig/zig-out/bin/crimson-zig")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    binary = args.out / "crimson-zig"
    binary.write_bytes(args.zig.read_bytes())
    binary.chmod(0o755)
    binary_sha = sha(binary.read_bytes())
    rows = []
    for preserve in (False, True):
        for held_g in (False, True):
            name = f"preserve-{int(preserve)}-g-{int(held_g)}"
            recorder = ReplayRecorder(ReplayHeader(
                game_mode_id=GameMode.SURVIVAL, seed=1, tick_rate=60, player_count=1, preserve_bugs=preserve,
            ))
            for tick in range(64):
                recorder.record_tick([PlayerInput(
                    aim=Vec2(800, 512), move_mode=MovementControlType.STATIC, fire_down=True,
                    fire_bullets_key_down=held_g and (tick < 16 or tick >= 32),
                )])
            replay = recorder.finish()
            driver = build_verify_playback_driver(replay)
            result = driver.run()
            player = driver.world.players[0]
            enabled = preserve and held_g
            assert (player.fire_bullets_timer > 0.0) == enabled, name
            types = {int(p.type_id) for p in driver.world.state.projectiles.entries if p.active}
            assert types == {45 if enabled else 1}, (name, types)
            replay.header = msgspec.structs.replace(replay.header, claimed_stats=ReplayClaimedStatsSnapshot(
                complete=True, ticks=result.ticks, elapsed_ms=result.elapsed_ms,
                score_xp=result.score_xp, kills=result.creature_kill_count,
                most_used_weapon_id=WeaponId(result.most_used_weapon_id),
                shots_fired=result.shots_fired, shots_hit=result.shots_hit,
            ))
            replay_path = args.out / f"{name}.crd"
            replay_path.write_bytes(dump_replay(replay))
            python_trace = args.out / f"{name}-python.cdt"
            zig_trace = args.out / f"{name}-zig.cdt"
            record_replay_to_trace(replay_path=replay_path, out_path=python_trace)
            zig = subprocess.run(
                [str(binary), "dbg", "record", str(replay_path), "--out", str(zig_trace)],
                capture_output=True, text=True, check=False,
            )
            assert zig.returncode == 0 and "warning:" not in zig.stdout + zig.stderr, (name, zig.stdout, zig.stderr)
            report = diff_report_to_json(diff_traces(expected_trace_path=python_trace, actual_trace_path=zig_trace))
            assert report["status"] == "ok" and report["checked_count"] == 64, (name, report)
            gameplay_rows = []
            for tick in iter_trace_ticks(python_trace):
                channels = msgspec.to_builtins(tick.channels)
                del channels["replay_step"]
                gameplay_rows.append(channels)
            gameplay_sha = sha(msgspec.json.encode(gameplay_rows))
            if not enabled and rows:
                assert gameplay_sha == rows[0]["gameplay_channels_sha256"], name
            rows.append({"name": name, "gameplay_channels_sha256": gameplay_sha, "preserve_bugs": preserve, "held_g": held_g,
                         "timer_final": player.fire_bullets_timer, "active_projectile_types": sorted(types),
                         "ammo_final": player.weapon.ammo, "shots_fired": result.shots_fired,
                         "replay_sha256": sha(replay_path.read_bytes()), "trace_comparison": report})
            print(name, "64 ticks equal", flush=True)
    (args.out / "port-results.json").write_text(json.dumps({
        "source_sha256": {path: sha((ROOT / path).read_bytes()) for path in SOURCES},
        "zig_binary_sha256": binary_sha, "cases": rows,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
