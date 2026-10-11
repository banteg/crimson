"""Convert a .crd replay into the core's .rsi input stream.

The .rsi file is the core's private test transport, not a public replay format:
it carries the run configuration (and a custom quest's table), inputs and commands,
and no claimed score. Decoding a replay does not make its rules or result
compatible with the core.
"""

import argparse
import struct
from pathlib import Path

from crimson.creatures.spawn_ids import SpawnId
from crimson.quests.custom import CustomQuest, variant_index
from crimson.quests.types import SpawnEntry
from crimson.replay.codec import load_replay_file
from crimson.sim.commands import PerkMenuOpenCommand, PerkPickCommand
from crimson.weapons import WeaponId
from grim.geom import Vec2

# `PortableQuest` in host/api.h: the weapon, three terrain slots and the entry count, then 256 entries.
QUEST_HEAD = struct.Struct("<5I")
QUEST_SPAWN = struct.Struct("<3f3i")
QUEST_BYTES = QUEST_HEAD.size + 256 * QUEST_SPAWN.size


def portable_quest(quest: CustomQuest, *, hardcore: bool) -> bytes:
    """The table the core plays: the one-player variant for the run's hardcore setting, with base counts."""
    table = quest.tables[quest.variants[variant_index(player_count=1, hardcore=hardcore)]]
    head = QUEST_HEAD.pack(quest.start_weapon_id, *quest.terrain_slots, len(table))
    entries = b"".join(
        QUEST_SPAWN.pack(e.pos.x, e.pos.y, e.heading, e.spawn_id, e.trigger_ms, e.count) for e in table
    )
    return (head + entries).ljust(QUEST_BYTES, b"\0")


def custom_quest(blob: bytes) -> CustomQuest:
    """The definition a `PortableQuest` holds: its one table plays every variant; the title is a stand-in."""
    weapon, *terrain, count = QUEST_HEAD.unpack_from(blob)
    table = tuple(
        SpawnEntry(pos=Vec2(x, y), heading=heading, spawn_id=SpawnId(template), trigger_ms=trigger, count=copies)
        for x, y, heading, template, trigger, copies in QUEST_SPAWN.iter_unpack(
            blob[QUEST_HEAD.size : QUEST_HEAD.size + count * QUEST_SPAWN.size],
        )
    )
    return CustomQuest(
        title="Custom quest",
        start_weapon_id=WeaponId(weapon),
        terrain_slots=(terrain[0], terrain[1], terrain[2]),
        tables=(table,),
        variants=(0,) * 8,
    )


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
        config += portable_quest(custom, hardcore=run.hardcore)
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
    parser.add_argument("--hardcore", action="store_true", help="with --recipe: the hardcore variant")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--ticks", type=int, default=None)
    args = parser.parse_args()
    if args.recipe is not None:
        from crimson.quests.dsl import build_custom_quest

        quest = build_custom_quest(args.recipe.read_text(encoding="utf-8"))
        args.out.write_bytes(portable_quest(quest, hardcore=args.hardcore))
    else:
        args.out.write_bytes(encode(load_replay_file(args.replay), args.ticks))


if __name__ == "__main__":
    main()
