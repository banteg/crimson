"""Corpse allocation and staged-death witnesses executed from the native image."""

import copy
import json
import struct
from pathlib import Path

from crimson.creatures.spawn import CreatureFlags, CreatureTypeId
from crimson.effects import FX_QUEUE_ROTATED_MAX_COUNT, FxQueueRotated, FxQueueRotatedEntry
from crimson.math_parity import f32
from grim.color import RGBA
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.factories import make_creature_state, make_step_runtime

FIXTURE = Path(__file__).resolve().parents[2] / "tests/fixtures/native/corpse-queue.json"


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


def fill_queue(queue: FxQueueRotated, count: int) -> FxQueueRotated:
    for index in range(count):
        assert queue.add(top_left=Vec2(index, -index), rgba=RGBA(0.2, 0.3, 0.4, 0.5),
                         rotation=0.1, scale=3.0, creature_type_id=2)
    return queue


def test_corpse_queue_matches_native_fields_capacity_and_failure() -> None:
    witnesses = json.loads(FIXTURE.read_text())["queue"]
    assert len(witnesses) == 240
    for witness in witnesses:
        case, expected = witness["input"], witness["expected"]
        queue = fill_queue(FxQueueRotated(), case["count"])
        previous = copy.deepcopy(queue.entries)
        queue.bodies_transparency = case["transparency"]
        accepted = queue.add(
            top_left=Vec2(*case["pos"]), rgba=RGBA(*case["color"]), rotation=case["rotation"],
            scale=case["scale"], creature_type_id=case["type_id"], terrain_texture_failed=bool(case["failed"]),
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
        world = make_world(preserve_bugs=True)
        world.players[0].pos = Vec2(300, 400)
        world.state.violence_disabled = case["violence"]
        step_runtime = make_step_runtime(world, dt=case["dt"])
        queue = fill_queue(step_runtime.fx_queue_rotated, 0 if case["queued"] else 63)
        initial_count = queue.count
        pool = world.creatures
        creature = make_creature_state(
            pos=Vec2(f32(row["pos_x"]), f32(row["pos_y"])), hp=row["health"], active=True,
            death_timer=f32(row["death_timer"]), size=f32(row["size"]), flags=CreatureFlags(row["flags"]),
        )
        creature.type_id = CreatureTypeId(row["type_id"])
        creature.heading = f32(row["heading"])
        creature.tint = RGBA(*(f32(row[f"tint_{channel}"]) for channel in "rgba"))
        pool.entries[0] = creature
        pool.update(step_runtime)
        assert bits(creature.death_timer) == expected["lifecycle_bits"], case
        assert pool.kill_count == expected["kill_count"], case
        assert queue.count == initial_count + int(expected["entry"] is not None), case
        if expected["entry"] is not None:
            assert entry_bits(queue.entries[initial_count]) == expected["entry"], case


def test_corpse_bake_retries_then_releases_the_faded_slot_after_render() -> None:
    world = make_world()
    pool = world.creatures
    corpse = pool.entries[0]
    corpse.active = True
    corpse.flags = CreatureFlags.SPAWNER
    corpse.link_index = 0
    pool.spawn_slots[0].owner_creature = 0
    corpse.death_timer = 1.0
    step = make_step_runtime(world, dt=0.5)
    queue = fill_queue(step.fx_queue_rotated, FX_QUEUE_ROTATED_MAX_COUNT)

    pool.update(step)
    assert corpse.death_timer == f32(0.001)
    assert pool.kill_count == 0

    queue.clear()
    # End the retry exactly at zero so the next half-second fade lands on −10.
    step.dt = f32(corpse.death_timer / 28.0)
    pool.update(step)
    assert corpse.death_timer == 0.0
    assert queue.count == 1
    assert pool.kill_count == 1

    step.dt = 0.5
    pool.update(step)
    assert corpse.death_timer == -10.0
    pool.release_faded_corpses_after_render()
    assert corpse.active
    assert pool.spawn_slots[0].owner_creature == 0

    pool.update(step)
    assert corpse.active
    assert queue.count == 1
    assert pool.kill_count == 1
    pool.release_faded_corpses_after_render()
    assert not corpse.active
    assert pool.spawn_slots[0].owner_creature == -1
