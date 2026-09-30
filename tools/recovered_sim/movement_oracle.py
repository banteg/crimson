"""Adjudicate the old snapshot-257 divergence with real x87 movement fragments.

This is a targeted, unobstructed dual-pad movement case with no perks or
speed/reflex boost. It checks a sampled replay state, not whole-run equivalence.
"""

import argparse
import json
import struct
import subprocess
from pathlib import Path

import msgspec
from builder_oracle import read_snapshots
from replay import encode

from crimson.math_parity import f32
from crimson.replay.codec import load_replay_file
from crimson.replay.ticks import step_replay_tick
from crimson.sim.run_init import initialize_run
from crimson_re.dbg.native_oracle import NativeOracle

HERE = Path(__file__).resolve().parent
LAYOUT = {
    "pos_x": 0x14,
    "pos_y": 0x18,
    "move_dx": 0x1C,
    "move_dy": 0x20,
    "heading": 0x2C,
    "aim_x": 0x50,
    "aim_y": 0x54,
    "move_speed": 0x68,
    "aim_heading": 0x300,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--replay", type=Path, required=True)
    parser.add_argument("--native", type=Path, default=HERE / "build/native/core")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    replay = load_replay_file(args.replay)
    session = initialize_run(msgspec.structs.replace(replay.run, preserve_bugs=True)).session
    for tick in replay.ticks[:256]:
        step_replay_tick(session, tick)
    player = session.world.players[0]
    if any(session.world.state.perks.counts) or player.aux_timer > 0 or session.world.state.bonuses.reflex_boost > 0:
        raise ValueError("This probe requires the unboosted, perk-free snapshot-257 fixture")
    names = [
        f"{g['name']}{f'[{i}]' if g['count'] > 1 else ''}.{field}"
        for g in json.loads((HERE / "schema.json").read_text())
        for i in range(g["count"])
        for field in g["fields"]
    ]
    data = subprocess.check_output([str(args.native)], input=encode(replay, 257))
    snapshots = read_snapshots(data)

    def field(snapshot, name, kind="f"):
        return struct.unpack_from("<" + kind, snapshot, names.index(name) * 4)[0]

    before = {name: field(snapshots[256], "players[0]." + name) for name in LAYOUT}
    actual = {name: field(snapshots[257], "players[0]." + name) for name in LAYOUT}
    if (before["pos_x"], before["pos_y"], before["heading"], before["move_speed"]) != (
        player.pos.x,
        player.pos.y,
        player.heading,
        player.move_speed,
    ):
        raise ValueError("Replay already diverged before the sampled movement case")
    mx, my, ax, ay, _ = replay.ticks[256].inputs[0]
    oracle = NativeOracle(args.exe)
    oracle.run_static_initializers()
    # Select the real x87 dispatch target rather than stubbing Normalize.
    thunk = oracle.read(oracle.resolve("D3DXVec2Normalize"), 6)
    if thunk[:2] != b"\xff\x25":
        raise ValueError("Unexpected D3DX dispatch thunk")
    oracle.write_u32(struct.unpack("<I", thunk[2:])[0], 0x00455587)
    slot = oracle.resolve("player_state_table")
    for name, value in before.items():
        oracle.write_f32(slot + LAYOUT[name], value)
    oracle.write_u32(slot + 0x2C0, field(snapshots[256], "players[0].weapon_id", "I"))
    oracle.write_u32("render_overlay_player_index", 0)
    oracle.write_f32("frame_dt", f32(1 / 60))
    regs = {"edi": slot, "esi": slot + 0x14, "ebp": 0x40000000}
    frame = bytearray(0x80)
    struct.pack_into("<2f", frame, 0x38, -mx, -my)
    oracle.run(0x0041421E, 0x00414276, regs=regs, frame=bytes(frame))
    target = oracle.read_f32(oracle.frame_pointer() + 0x20)
    frame = bytearray(0x80)
    struct.pack_into("<2f", frame, 0x1C, player.speed_multiplier, target)
    oracle.run(0x00414276, 0x0041438B, regs=regs, frame=bytes(frame))
    dx = oracle.read_f32(oracle.frame_pointer() + 0x48)
    dy = oracle.read_f32(oracle.frame_pointer() + 0x4C)
    # This sampled step is in the arena interior with no spawn-slot avoidance.
    oracle.write_f32(slot + 0x14, f32(before["pos_x"] + dx))
    oracle.write_f32(slot + 0x18, f32(before["pos_y"] + dy))
    oracle.write_f32(slot + 0x50, ax)
    oracle.write_f32(slot + 0x54, ay)
    oracle.run(0x0041572E, 0x00415753, regs=regs)
    expected = {name: oracle.read_f32(slot + offset) for name, offset in LAYOUT.items()}
    step_replay_tick(session, replay.ticks[256])
    python = {
        "pos_x": player.pos.x,
        "pos_y": player.pos.y,
        "heading": player.heading,
        "move_speed": player.move_speed,
        "aim_heading": player.aim_heading,
    }
    differences = {
        key: {"original": value, "recovered": actual[key]}
        for key, value in expected.items()
        if struct.pack("<f", value) != struct.pack("<f", actual[key])
    }
    report = {
        "snapshot": 257,
        "python_preserve_bugs": True,
        "scope": "sampled unboosted dual-pad movement and final aim fragments",
        "original": expected,
        "recovered": actual,
        "python": python,
        "original_mismatches": differences,
    }
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if differences:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
