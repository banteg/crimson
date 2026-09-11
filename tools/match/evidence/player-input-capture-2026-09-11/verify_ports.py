"""Record captured auto-fire inputs and compare complete Python/Zig replay ticks."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

import msgspec

from crimson.dbg.diff import diff_report_to_json, diff_traces
from crimson.dbg.record import record_replay_to_trace
from crimson.game_modes import GameMode
from crimson.replay import ReplayClaimedStatsSnapshot, ReplayHeader, ReplayRecorder, dump_replay
from crimson.replay.driver.playback_driver import build_verify_playback_driver
from crimson.replay.input_codec import unpack_player_input
from crimson.weapons import WeaponId

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--zig", type=Path, default=ROOT / "crimson-zig/zig-out/bin/crimson-zig")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    receipt = json.loads(args.native.read_text())
    assert receipt["agent_sha256"] == sha((ROOT / "scripts/frida/gameplay_diff_capture.js").read_bytes())
    assert receipt["harness_sha256"] == sha((HERE / "harness.js").read_bytes())
    binary = args.out / "crimson-zig"
    binary.write_bytes(args.zig.read_bytes())
    binary.chmod(0o755)
    rows = []
    for native in receipt["results"]:
        if native["name"] not in receipt["before_port_mismatches"]:
            continue
        for version in ("before", "current"):
            name = native["name"] + "-" + version
            inputs = [unpack_player_input(row) for row in native[version]["inputs"]]
            released = [msgspec.structs.replace(row, fire_down=False, fire_pressed=False, fire_bullets_key_down=False)
                        for row in inputs]
            recorder = ReplayRecorder(ReplayHeader(
                game_mode_id=GameMode.SURVIVAL, seed=1, tick_rate=60, player_count=2, preserve_bugs=True,
            ))
            # A reset starts with a native 0.8s cooldown. Give the transport
            # control one neutral second before applying the ready-shot witness.
            for tick in range(80):
                recorder.record_tick(inputs if tick == 60 else released)
            replay = recorder.finish()
            driver = build_verify_playback_driver(replay)
            result = driver.run()
            players = driver.world.players
            owner = native["frame"]["index"]
            shot_counts = driver.world.state.shots_fired[:2]
            assert shot_counts == [int(version == "current" and i == owner) for i in (0, 1)], (name, shot_counts)
            # The replay's score/claimed-stat surface follows player zero.
            assert result.shots_fired == shot_counts[0]
            expected_g = version == "current" and 0x22 in native["frame"]["keys"]
            assert (players[owner].fire_bullets_timer > 0.0) == expected_g, name
            assert players[1 - owner].fire_bullets_timer == 0.0, name
            replay.header = msgspec.structs.replace(replay.header, claimed_stats=ReplayClaimedStatsSnapshot(
                complete=True, ticks=result.ticks, elapsed_ms=result.elapsed_ms,
                score_xp=result.score_xp, kills=result.creature_kill_count,
                most_used_weapon_id=WeaponId(result.most_used_weapon_id),
                shots_fired=result.shots_fired, shots_hit=result.shots_hit,
            ))
            replay_path = args.out / (name + ".crd")
            replay_path.write_bytes(dump_replay(replay))
            python_trace, zig_trace = (args.out / (name + suffix) for suffix in ("-python.cdt", "-zig.cdt"))
            record_replay_to_trace(replay_path=replay_path, out_path=python_trace)
            zig = subprocess.run([str(binary), "dbg", "record", str(replay_path), "--out", str(zig_trace)],
                                 capture_output=True, text=True, check=False)
            assert zig.returncode == 0 and "warning:" not in zig.stdout + zig.stderr, (name, zig.stdout, zig.stderr)
            report = diff_report_to_json(diff_traces(expected_trace_path=python_trace, actual_trace_path=zig_trace))
            assert report["status"] == "ok" and report["checked_count"] == 80, (name, report)
            rows.append({
                "name": name, "shots_fired_by_player": shot_counts, "owner": owner,
                "fire_bullets_timers": [player.fire_bullets_timer for player in players],
                "ammo": [player.weapon.ammo for player in players],
                "replay_sha256": sha(replay_path.read_bytes()), "trace_comparison": report,
            })
            print(name, "80 ticks equal", flush=True)
    assert len(rows) == 8
    source_paths = (
        "scripts/frida/gameplay_diff_capture.js", "src/crimson/replay/input_codec.py", "src/crimson/replay/types.py",
        "src/crimson/gameplay.py", "src/crimson/weapon_runtime/fire.py", "src/crimson/sim/input.py",
        "crimson-zig/src/replay_codec.zig", "crimson-zig/src/runtime/player.zig", "crimson-zig/src/runtime/weapons.zig",
        "crimson-zig/src/runtime/replay_runner.zig", "crimson-zig/src/runtime/replay/step.zig",
        "crimson-zig/src/dbg_verify_native.zig",
    )
    (args.out / "port-results.json").write_text(json.dumps({
        "native_receipt_sha256": sha(args.native.read_bytes()), "verifier_sha256": sha(Path(__file__).read_bytes()),
        "zig_binary_sha256": sha(binary.read_bytes()),
        "source_sha256": {name: sha((ROOT / name).read_bytes()) for name in source_paths}, "cases": rows,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
