"""Convert a .crd replay into the core's .rsi input stream.

The .rsi file is the core's private test transport, not a public replay format:
it carries the run configuration, inputs and commands, and no claimed score.
Decoding a replay does not make its rules or result compatible with the core.
"""

import argparse
import struct
from pathlib import Path

from crimson.replay.codec import load_replay_file
from crimson.sim.commands import PerkMenuOpenCommand, PerkPickCommand


def encode(replay, limit):
    run = replay.run
    if run.player_count != 1 or int(run.game_mode_id) not in (1, 2, 3):
        raise ValueError("The core supports one player in Rush, Survival or Quests")
    level = run.quest_level
    config = struct.pack(
        "<65I",
        run.seed,
        int(run.game_mode_id),
        level.major if level else 1,
        level.minor if level else 1,
        run.status.quest_unlock_index,
        run.status.quest_unlock_index_hardcore,
        run.detail_preset,
        run.violence_disabled,
        run.friendly_fire,
        run.hardcore,
        run.quest_fail_retry_count,
        run.preserve_bugs,
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
        records.append(
            struct.pack("<4fII", mx, my, ax, ay, flags, len(commands))
            + b"".join(struct.pack("<ii", *command) for command in commands),
        )
    return config + b"".join(records)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("replay", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--ticks", type=int, default=None)
    args = parser.parse_args()
    args.out.write_bytes(encode(load_replay_file(args.replay), args.ticks))


if __name__ == "__main__":
    main()
