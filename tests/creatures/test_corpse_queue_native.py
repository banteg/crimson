"""Corpse allocation and staged-death witnesses executed from the native image."""

import copy
import json
import struct
from pathlib import Path

from crimson.creatures.runtime import CreaturePool
from crimson.creatures.spawn import CreatureFlags, CreatureTypeId
from crimson.effects import FxQueueRotated, FxQueueRotatedEntry
from crimson.math_parity import f32
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.color import RGBA
from grim.geom import Vec2
from tests.support.factories import make_creature_state, make_creature_update_options

FIXTURE = Path(__file__).resolve().parents[2] / "crimson-zig/src/runtime/testdata/corpse-queue.json"


def bits(value: float) -> int:
    return struct.unpack("<I", struct.pack("<f", value))[0]


def entry_bits(entry: FxQueueRotatedEntry) -> dict:
    return {
        "pos_bits": [bits(entry.top_left.x), bits(entry.top_left.y)],
        "color_bits": list(map(bits, (entry.color.r, entry.color.g, entry.color.b, entry.color.a))),
        "rotation_bits": bits(entry.rotation),
        "scale_bits": bits(entry.scale),
        "type_id": entry.creature_type_id,
    }


def filled_queue(count: int) -> FxQueueRotated:
    queue = FxQueueRotated()
    for index in range(count):
        assert queue.add(top_left=Vec2(index, -index), rgba=RGBA(0.2, 0.3, 0.4, 0.5),
                         rotation=0.1, scale=3.0, creature_type_id=2)
    return queue


def test_corpse_queue_matches_native_fields_capacity_and_failure() -> None:
    witnesses = json.loads(FIXTURE.read_text())["queue"]
    assert len(witnesses) == 240
    for witness in witnesses:
        case, expected = witness["input"], witness["expected"]
        queue = filled_queue(case["count"])
        previous = copy.deepcopy(queue.entries)
        accepted = queue.add(
            top_left=Vec2(*case["pos"]), rgba=RGBA(*case["color"]), rotation=case["rotation"],
            scale=case["scale"], creature_type_id=case["type_id"],
            terrain_bodies_transparency=case["transparency"], terrain_texture_failed=bool(case["failed"]),
        )
        assert accepted == bool(expected["return"]), case
        assert queue.count == expected["count"], case
        for index, old_entry in enumerate(previous):
            if expected["entry"] is not None and index == case["count"]:
                assert entry_bits(queue.entries[index]) == expected["entry"], case
            else:
                assert queue.entries[index] == old_entry, case


def test_staged_death_matches_native_corpse_tint_size_and_retry() -> None:
    witnesses = json.loads(FIXTURE.read_text())["callers"]
    assert len(witnesses) == 64
    for witness in witnesses:
        case, expected = witness["input"], witness["expected"]
        row = case["creatures"][0]
        queue = filled_queue(0 if case["queued"] else 63)
        initial_count = queue.count
        pool = CreaturePool()
        state = GameplayState(preserve_bugs=True)
        creature = make_creature_state(
            pos=Vec2(f32(row["pos_x"]), f32(row["pos_y"])), hp=row["health"], active=True,
            lifecycle_stage=f32(row["lifecycle_stage"]), size=f32(row["size"]), flags=CreatureFlags(row["flags"]),
        )
        creature.type_id = CreatureTypeId(row["type_id"])
        creature.heading = f32(row["heading"])
        creature.tint = RGBA(*(f32(row[f"tint_{channel}"]) for channel in "rgba"))
        pool.entries[0] = creature
        pool.update(case["dt"], options=make_creature_update_options(
            state=state, players=[PlayerState(index=0, pos=Vec2(300, 400), health=100)],
            violence_disabled=case["violence"], fx_queue_rotated=queue,
        ))
        assert bits(creature.lifecycle_stage) == expected["lifecycle_bits"], case
        assert pool.kill_count == expected["kill_count"], case
        assert queue.count == initial_count + int(expected["entry"] is not None), case
        if expected["entry"] is not None:
            assert entry_bits(queue.entries[initial_count]) == expected["entry"], case
