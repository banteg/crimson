"""Deterministic microstep-boundary inputs and compiled native layout checks."""

import copy
import random
import struct
from dataclasses import replace

from execute import POOLS, F, m, match

# Counterexamples discovered in the 500-case PC24 matrix against 7ec7c1918.
COLLISION_SEEDS = (22, 27, 46, 72, 102, 136, 137, 167, 177, 197, 198, 202, 218, 237, 257, 317, 361, 431, 452, 457, 478)


def check_layout(config, out):
    layout = {}
    for name, (count, size) in POOLS.items():
        layout[f"sizeof({name}) / sizeof({name}[0])"] = count
        layout[f"sizeof({name}[0])"] = size
    owners = {
        "primary": (
            "projectile_t",
            {
                "x": "pos_x",
                "y": "pos_y",
                "origin_x": "origin_x",
                "origin_y": "origin_y",
                "vx": "vel_x",
                "vy": "vel_y",
                "type": "type_id",
                "life": "life_timer",
                "speed": "speed_scale",
                "damage": "damage_pool",
                "radius": "hit_radius",
                "travel": "travel_budget",
                "owner": "owner_id",
            },
        ),
        "players": (
            "player_state_t",
            {"active": "entity_active", "x": "pos_x", "y": "pos_y", "shield": "shield_timer"},
        ),
    }
    for category, (owner, names) in owners.items():
        for field, (offset, fmt) in F[category].items():
            name = names.get(field, field)
            if category == "primary" and field in names:
                name = "fields." + name
            layout[f"offsetof({owner}, {name})"] = offset
            layout[f"sizeof((({owner} *)0)->{name})"] = struct.calcsize(fmt)
    layout["sizeof(config_blob.player_count)"] = 4
    directory = out / "layout"
    directory.mkdir(exist_ok=True)
    source = '#include "crimsonland_gameplay.h"\n#include <stddef.h>\nextern "C" { unsigned int execution_offsets[] = {'
    source += ", ".join(layout) + "}; }\n"
    (directory / "scratch.cpp").write_text(source)
    obj = match.parse_coff_object(match.compile_scratch(replace(config, directory=directory)).read_bytes())
    symbol = next(row for row in obj.symbols if row.name == "_execution_offsets")
    raw = obj.sections[symbol.section_number - 1].data[symbol.value : symbol.value + 4 * len(layout)]
    assert list(struct.unpack("<" + "I" * len(layout), raw)) == list(layout.values())
    return layout


def movement_cases():
    rng = random.Random(2026091107)
    for index in range(500):
        speed = m.f32(rng.uniform(0.1, 5))
        dt = m.f32(4 / (60 * speed))
        bits = struct.unpack("<I", struct.pack("<f", dt))[0] + index % 5 - 2
        dt = struct.unpack("<f", struct.pack("<I", bits))[0]
        yield {
            "fpcw": 0x7F,
            "dt": dt,
            "rng_seed": 19,
            "primary": [
                {
                    "index": index % 96,
                    "angle": m.f32(rng.uniform(-7, 7)),
                    "x": m.f32(rng.uniform(50, 900)),
                    "y": m.f32(rng.uniform(50, 900)),
                    "type": 1,
                    "life": 1,
                    "speed": speed,
                    "radius": 1,
                    "travel": (6, 9, 12)[index % 3],
                    "owner": -100,
                },
            ],
        }


def player_cases(movement_witnesses):
    for seed in COLLISION_SEEDS:
        witness = movement_witnesses[seed]
        for mode in ("unshielded", "shielded", "dead", "owner", "shock-chain"):
            case = copy.deepcopy(witness["input"])
            case["seed_index"] = seed
            case["mode"] = mode
            projectile = case["primary"][0]
            projectile["owner"] = -1 if mode == "owner" else 0
            if mode == "shock-chain":
                case["shock_id"] = projectile["index"]
            x, y = witness["creature_queries"][0]
            case["players"] = [
                {
                    "index": 0,
                    "x": x,
                    "y": y,
                    "health": 0 if mode == "dead" else 100,
                    "size": 50,
                    "shield": 1 if mode == "shielded" else 0,
                },
            ]
            yield case
