"""Native `quest_build_*` functions vs the port's quest builders.

Runs each of the 50 original quest builders on a zeroed entry buffer with the
CRT `rand()` seed shared, then compares every `quest_spawn_entry_t` field
(float position and heading, template id, trigger time, count), the entry
count and the final RNG state bit for bit with the port's builder.  The
hardcore spawn-table adjustment runs later in `quest_start_selected` and is
outside this check; the builders' own `config_hardcore` reads are covered.
"""

from __future__ import annotations

import random
import re
import struct

from crimson.quests import QUESTS
from crimson.quests.types import QuestContext, QuestDefinition
from crimson.sim.state_types import TERRAIN_SIZE
from grim.rand import CrtRand

from ._support import Mismatch, compare_fields, mismatch_report

# `quest_spawn_entry_t` (0x18 bytes).
_ENTRY_STRIDE = 0x18
_ENTRY_LAYOUT: dict[str, tuple[int, str]] = {
    "pos_x": (0x00, "f"),
    "pos_y": (0x04, "f"),
    "heading": (0x08, "f"),
    "spawn_id": (0x0C, "i"),
    "trigger_ms": (0x10, "i"),
    "count": (0x14, "i"),
}
_ENTRY_FORMAT = struct.Struct("<" + "".join(fmt for _offset, fmt in _ENTRY_LAYOUT.values()))
_ENTRY_CAPACITY = 0x400
_SEEDS = (0, 1, 1337, 0xBEEF, 0x7FFF_FFFF, 0xDEADBEEF, *random.Random(0x437A00).choices(range(1 << 32), k=26))
# (player count, hardcore): the builders read `config_player_count` and
# `config_hardcore`; the terrain globals stay at the native 1024.
_ENVIRONMENTS = (
    (1, False),
    (2, True),
    (3, False),
    (1, True),
    (4, True),
)


def _native_builder_name(quest: QuestDefinition) -> str:
    return "quest_build_" + re.sub(r"[^a-z0-9]+", "_", quest.title.lower()).strip("_")


def test_quest_builders_match_native(oracle) -> None:
    entries = oracle.alloc(_ENTRY_STRIDE * _ENTRY_CAPACITY)
    count_ptr = oracle.alloc(4)
    pristine = oracle.snapshot()

    mismatches: list[Mismatch] = []
    cases = 0
    for quest in QUESTS:
        builder = oracle.resolve(_native_builder_name(quest))
        for player_count, hardcore in _ENVIRONMENTS:
            for seed in _SEEDS:
                cases += 1
                case = f"{quest.level.text} players={player_count} hardcore={hardcore} seed=0x{seed:08x}"
                oracle.restore(pristine)
                oracle.write_u32("terrain_texture_width", TERRAIN_SIZE)
                oracle.write_u32("terrain_texture_height", TERRAIN_SIZE)
                oracle.write_u32("config_player_count", player_count)
                oracle.write_u8("config_hardcore", int(hardcore))
                oracle.rand_state = seed
                oracle.call(builder, entries, count_ptr)

                rng = CrtRand(seed)
                python_entries = quest.builder(QuestContext(player_count=player_count, hardcore=hardcore, rng=rng))

                native_count = oracle.read_i32(count_ptr)
                if native_count != len(python_entries):
                    mismatches.append(Mismatch(case, "entry_count", native_count, len(python_entries), count_ptr))
                if oracle.rand_state != rng.state:
                    mismatches.append(Mismatch(case, "rand_state", oracle.rand_state, rng.state, 0))
                native_rows = oracle.read(entries, _ENTRY_STRIDE * min(native_count, len(python_entries)))
                for index, entry in enumerate(python_entries[:native_count]):
                    address = entries + index * _ENTRY_STRIDE
                    native = dict(zip(_ENTRY_LAYOUT, _ENTRY_FORMAT.unpack_from(native_rows, index * _ENTRY_STRIDE), strict=True))
                    python = {
                        "pos_x": entry.pos.x,
                        "pos_y": entry.pos.y,
                        "heading": entry.heading,
                        "spawn_id": int(entry.spawn_id),
                        "trigger_ms": entry.trigger_ms,
                        "count": entry.count,
                    }
                    mismatches += compare_fields(f"{case} entry[{index}]", native, python, address=address)
    assert not mismatches, mismatch_report(mismatches, total_cases=cases)
