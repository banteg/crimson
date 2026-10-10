#!/usr/bin/env python3
"""Bounded saturated-pool Survival wave benchmark; run in each checkout with PYTHONPATH=.:src."""

import argparse
import hashlib
import json
import statistics
import time
from pathlib import Path

import msgspec

from crimson.creatures.runtime import PHANTOM_CREATURE_INDEX
from crimson.sim.mode_updates import SurvivalSpawnState, survival_update
from tests.support.builders.session import make_world


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    rows = []
    for elapsed_ms in (900_000, 1_800_000, 2_154_555):
        samples = []
        for repeat in range(4):
            world = make_world(seed=97)
            world.state.survival_shrinkifier_handout_enabled = False
            world.players[0].experience = 143_802_723
            for creature in world.creatures.entries:
                creature.active = True
            spawn = SurvivalSpawnState(stage=10)
            start = time.perf_counter()
            survival_update(world, spawn, elapsed_ms=elapsed_ms, dt_ms=16)
            ms = (time.perf_counter() - start) * 1000
            snapshot = msgspec.msgpack.encode((
                world.creatures.entries, world.creatures.phantom,
                world.creatures.alloc_count, world.creatures.spawned_count,
                world.state.rng.state, spawn,
            ))
            samples.append({"repeat": repeat, "ms": ms, "hash": hashlib.sha256(snapshot).hexdigest()})
        rows.append({
            "elapsed_ms": elapsed_ms, "dt_ms": 16, "samples": samples,
            "warm_median_ms": statistics.median(sample["ms"] for sample in samples[1:]),
        })
    args.out.write_text(json.dumps({
        "rows": rows, "pool_slots": PHANTOM_CREATURE_INDEX, "seed": 97, "xp": 143_802_723,
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
