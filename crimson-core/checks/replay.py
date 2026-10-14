"""Convert a .crd replay into the core's .rsi input stream.

The .rsi file is the core's private test transport, not a public replay format:
it carries the run configuration (and a custom quest's table), inputs and commands,
and no claimed score. Decoding a replay does not make its rules or result
compatible with the core.
"""

import argparse
import struct
from pathlib import Path

from crimson.quests.custom import PORTABLE_QUEST_BYTES, CustomQuest
from crimson.replay.codec import load_replay_file
from crimson.sim.commands import PerkMenuOpenCommand, PerkPickCommand

QUEST_BYTES = PORTABLE_QUEST_BYTES


def portable_quest(quest: CustomQuest) -> bytes:
    """The table and restriction bitmasks the core plays."""
    return quest.to_portable_bytes()


def custom_quest(blob: bytes) -> CustomQuest:
    """The definition a `PortableQuest` holds; the title is a stand-in."""
    return CustomQuest.from_portable_bytes(blob)


def encode(replay, limit):
    run = replay.run
    if run.player_count != 1 or int(run.game_mode_id) not in (1, 2, 3):
        raise ValueError("The core supports one player in Rush, Survival or Quests")
    level = run.quest_level
    custom = run.custom_quest
    # A custom quest starts at stage 0.0, its table after the config.
    stage = (0, 0) if custom is not None else (level.major, level.minor) if level else (1, 1)
    config = struct.pack(
        "<65I",
        run.seed,
        int(run.game_mode_id),
        *stage,
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
    if custom is not None:
        config += portable_quest(custom)
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
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("replay", type=Path, nargs="?")
    source.add_argument("--recipe", type=Path, help="write a quest recipe's PortableQuest instead")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--ticks", type=int, default=None)
    args = parser.parse_args()
    if args.recipe is not None:
        from crimson.quests.dsl import build_custom_quest

        quest = build_custom_quest(args.recipe.read_text(encoding="utf-8"))
        args.out.write_bytes(portable_quest(quest))
    else:
        args.out.write_bytes(encode(load_replay_file(args.replay), args.ticks))


if __name__ == "__main__":
    main()
