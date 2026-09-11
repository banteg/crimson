"""Reachable primary impacts, distinct precision modes, and header layout proof."""

import math
import random
import struct
from dataclasses import replace

from execute import CATEGORIES, POOLS, F, m, match, run


def check_layout(config, out):
    layout = {}
    for name, (count, size) in POOLS.items():
        if name == "effect_template":
            layout["sizeof(effect_template)"] = size
        else:
            layout[f"sizeof({name}) / sizeof({name}[0])"] = count
            layout[f"sizeof({name}[0])"] = size
    names = {
        "primary": (
            "projectile_t",
            {
                "x": "fields.pos_x",
                "y": "fields.pos_y",
                "origin_x": "fields.origin_x",
                "origin_y": "fields.origin_y",
                "vx": "fields.vel_x",
                "vy": "fields.vel_y",
                "type": "fields.type_id",
                "life": "fields.life_timer",
                "speed": "fields.speed_scale",
                "damage": "fields.damage_pool",
                "radius": "fields.hit_radius",
                "travel": "fields.travel_budget",
                "owner": "fields.owner_id",
            },
        ),
        "creatures": (
            "creature_t",
            {
                "lifecycle": "lifecycle_stage",
                "x": "pos_x",
                "y": "pos_y",
                "vx": "vel_x",
                "vy": "vel_y",
                "hit_flash": "hit_flash_timer",
                "r": "tint_r",
                "g": "tint_g",
                "b": "tint_b",
                "a": "tint_a",
                "type": "type_id",
            },
        ),
    }
    for category, (owner, fields) in names.items():
        for field, (offset, fmt) in F[category].items():
            name = fields.get(field, field)
            layout[f"offsetof({owner}, {name})"] = offset
            layout[f"sizeof((({owner} *)0)->{name})"] = struct.calcsize(fmt)
    for field, offset in {
        "velocity": 0,
        "rotation": 8,
        "scale": 12,
        "half_extent": 16,
        "age": 24,
        "lifetime": 28,
        "flags": 32,
        "color": 36,
        "rotation_step": 52,
        "scale_step": 56,
    }.items():
        layout[f"offsetof(effect_template_t, {field})"] = offset
    layout["offsetof(weapon_stats_t, damage_scale)"] = 112
    layout["sizeof(((weapon_stats_t *)0)->damage_scale)"] = 4
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


def fields(trace, category, index):
    name = CATEGORIES[category]
    return {
        field: struct.unpack_from("<" + fmt, trace["state"][name], index * POOLS[name][1] + offset)[0]
        for field, (offset, fmt) in F[category].items()
    }


def scenarios(program, count):
    rng = random.Random(2026091110)
    for index in range(count):
        mode = ("independent-origin", "spawn-position", "straight-travel")[index % 3]
        item = {
            "index": index % 96,
            "angle": m.f32(rng.uniform(-7, 7)),
            "x": m.f32(rng.uniform(50, 900)),
            "y": m.f32(rng.uniform(50, 900)),
            "origin_x": m.f32(rng.uniform(50, 900)),
            "origin_y": m.f32(rng.uniform(50, 900)),
            "type": 1,
            "life": 1,
            "speed": m.f32(rng.uniform(0.1, 5)),
            "radius": 1,
            "travel": 3,
            "damage": 1,
            "owner": -100,
        }
        if mode == "spawn-position":
            item["origin_x"], item["origin_y"] = item["x"], item["y"]
        elif mode == "straight-travel":
            angle = m.f32(item["angle"] - m.f32(math.pi / 2))
            item["origin_x"] = m.f32(item["x"] - math.cos(angle) * 200)
            item["origin_y"] = m.f32(item["y"] - math.sin(angle) * 200)
        case = {
            "mode": mode,
            "fpcw": 0x7F,
            "dt": m.f32(rng.uniform(0.001, 0.1)),
            "rng_seed": rng.randrange(2**32),
            "violence_disabled": (index // 3) % 2,
            "perks": [1] if (index // 6) % 2 else [],
            "template_fill": index % 256,
            # The native helper preserves this shared field. Test the same
            # starting scale as the port, without claiming global-template parity.
            "template_scale": 1,
            "damage_scale": m.f32(4.1),
            "primary": [item],
        }
        preflight = run(program, True, case)
        query = next(call for call in preflight["calls"] if call[0] == "creature_find_in_radius")
        x, y = struct.unpack("<2f", struct.pack("<2I", *query[1]))
        case["creatures"] = [
            {"index": index % 384, "x": x, "y": y, "health": 1000, "max_health": 1000, "size": 50, "lifecycle": 16},
        ]
        yield case
