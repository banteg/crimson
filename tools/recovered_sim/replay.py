"""Reuse the current .crd decoder and normalized inputs for the spike harness.

The .rsi file is a private test transport, not a new public replay format. It
contains no claimed score. The recovered core always retains original bugs;
decoding a Python replay does not imply that its rules or result are compatible.
"""

import argparse
import json
import struct
import subprocess
import tempfile
from pathlib import Path

import msgspec

from crimson.replay.codec import load_replay_file
from crimson.replay.ticks import step_replay_tick
from crimson.sim.commands import PerkMenuOpenCommand, PerkPickCommand
from crimson.sim.run_init import initialize_run

HERE = Path(__file__).resolve().parent


def encode(replay, limit):
    run = replay.run
    if run.player_count != 1 or int(run.game_mode_id) not in (1, 2, 3):
        raise ValueError("Spike supports one player in Rush, Survival or Quests")
    level = run.quest_level
    config = struct.pack(
        "<64I",
        run.seed,
        int(run.game_mode_id),
        level.major if level else 1,
        level.minor if level else 1,
        run.status.quest_unlock_index,
        run.status.quest_unlock_index_full,
        run.detail_preset,
        run.violence_disabled,
        run.friendly_fire,
        run.hardcore,
        run.quest_fail_retry_count,
        *run.status.weapon_usage_counts,
    )
    records = []
    for tick in replay.ticks[:limit]:
        if len(tick.inputs) != 1 or len(tick.commands) > 16:
            raise ValueError("Unsupported player or command count")
        commands = []
        for command in tick.commands:
            if command.player_index != 0:
                raise ValueError("Unsupported command player")
            match command:
                case PerkPickCommand(choice_index=choice):
                    commands.append((1, choice))
                case PerkMenuOpenCommand():
                    commands.append((2, 0))
                case _:
                    raise ValueError(f"Unsupported command: {command}")
        mx, my, ax, ay, flags = tick.inputs[0]
        if flags & ~(1 | 2 | 4 | 8 | 65536 | 131072) not in (0x1700, 0x9700):
            raise ValueError("Spike supports dual-action movement with mouse or dual action pad aim")
        records.append(
            struct.pack("<4fII", mx, my, ax, ay, flags, len(commands))
            + b"".join(struct.pack("<ii", *command) for command in commands),
        )
    return config + b"".join(records)


def diagnose(replay, payload, native, *, preserve_bugs=None):
    schema = json.loads((HERE / "schema.json").read_text())
    names = [
        f"{g['name']}{f'[{i}]' if g['count'] > 1 else ''}.{field}"
        for g in schema
        for i in range(g["count"])
        for field in g["fields"]
    ]
    indices = {n: i for i, n in enumerate(names)}
    expected_snapshots = 1
    offset = 256
    while offset < len(payload):
        command_count = struct.unpack_from("<I", payload, offset + 20)[0]
        offset += 24 + command_count * 8
        expected_snapshots += 1
    if offset != len(payload):
        raise ValueError("Truncated diagnostic input")
    reference_run = replay.run
    if preserve_bugs is not None:
        reference_run = msgspec.structs.replace(reference_run, preserve_bugs=preserve_bugs)
    session = initialize_run(reference_run).session
    first = {}
    snapshots = 0
    with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as errors:
        source.write(payload)
        source.seek(0)
        with subprocess.Popen([str(native)], stdin=source, stdout=subprocess.PIPE, stderr=errors) as proc:
            while header := proc.stdout.read(4):
                count = struct.unpack("<I", header)[0]
                data = proc.stdout.read(count * 4)
                if len(data) != count * 4 or count != len(names):
                    raise ValueError("Truncated or unknown native snapshot")
                if snapshots:
                    step_replay_tick(session, replay.ticks[snapshots - 1])
                player = session.world.players[0]
                checks = {
                    "globals.rng": session.world.state.rng.state,
                    "players[0].pos_x": player.pos.x,
                    "players[0].pos_y": player.pos.y,
                    "players[0].health": player.health,
                    "players[0].heading": player.heading,
                    "players[0].aim_heading": player.aim_heading,
                    "players[0].experience": player.experience,
                    "players[0].ammo": player.weapon.ammo,
                    "players[0].weapon_id": int(player.weapon.weapon_id),
                    "globals.highscore_record_shots_fired": session.world.state.shots_fired,
                    "globals.highscore_record_shots_hit": session.world.state.shots_hit,
                }
                for key, value in checks.items():
                    wanted = (
                        struct.pack("<f", value) if isinstance(value, float) else struct.pack("<I", value & 0xFFFFFFFF)
                    )
                    actual = data[indices[key] * 4 : indices[key] * 4 + 4]
                    if wanted != actual and key not in first:
                        first[key] = {
                            "snapshot": snapshots,
                            "python": value,
                            "recovered": struct.unpack("<f" if isinstance(value, float) else "<I", actual)[0],
                        }
                snapshots += 1
            code = proc.wait()
        errors.seek(0)
        stderr = errors.read().decode()
    return {
        "recorded_preserve_bugs": replay.run.preserve_bugs,
        "python_preserve_bugs": reference_run.preserve_bugs,
        "recovered_preserve_bugs": True,
        "snapshots": snapshots,
        "expected_snapshots": expected_snapshots,
        "native_exit": code,
        "native_stderr": stderr,
        "first_differences": first,
        "common_fields_compared": 11,
        "common_fields_equal": code == 0 and snapshots == expected_snapshots and not first,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("replay", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--ticks", type=int, default=None)
    parser.add_argument("--diagnose", type=Path, help="Native core for Python common-field comparison")
    parser.add_argument(
        "--preserve-bugs",
        action="store_true",
        default=None,
        help="Use original bugs in the Python diagnostic; does not change inputs or validate the recorded score",
    )
    args = parser.parse_args()
    replay = load_replay_file(args.replay)
    payload = encode(replay, args.ticks)
    args.out.write_bytes(payload)
    if args.diagnose:
        print(json.dumps(diagnose(replay, payload, args.diagnose, preserve_bugs=args.preserve_bugs), indent=2))


if __name__ == "__main__":
    main()
