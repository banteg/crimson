"""Reachable native impacts, boundary cases, and compiler-checked field layouts."""

import copy
import itertools
import math
import random
import struct
from dataclasses import replace

from execute import POOLS, F, m, match, run


def check_layout(config, out):
    directory = out / "layout"
    directory.mkdir(exist_ok=True)
    layout = {}
    for name, (count, size) in POOLS.items():
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
        "secondary": (
            "secondary_projectile_t",
            {
                "life": "life_timer",
                "x": "fields.pos_x",
                "y": "fields.pos_y",
                "vx": "fields.vel_x",
                "vy": "fields.vel_y",
                "type": "fields.type_id",
                "trail": "fields.trail_timer",
                "target": "fields.target_id",
            },
        ),
        "sprites": ("sprite_effect_t", {"alpha": "color_a", "x": "pos_x", "y": "pos_y", "vx": "vel_x", "vy": "vel_y"}),
        "particles": (
            "particle_t",
            {
                "render": "render_flag",
                "x": "pos_x",
                "y": "pos_y",
                "vx": "vel_x",
                "vy": "vel_y",
                "sx": "scale_x",
                "sy": "scale_y",
                "sz": "scale_z",
                "style": "style_id",
                "target": "target_id",
            },
        ),
    }
    names["creatures"] = (
        "creature_t",
        {
            "lifecycle": "lifecycle_stage",
            "x": "pos_x",
            "y": "pos_y",
            "vx": "vel_x",
            "vy": "vel_y",
            "r": "tint_r",
            "g": "tint_g",
            "b": "tint_b",
            "a": "tint_a",
            "type": "type_id",
            "hit_flash": "hit_flash_timer",
        },
    )
    for category, (owner, fields) in names.items():
        for field, (offset, fmt) in F[category].items():
            name = fields.get(field, field)
            layout[f"offsetof({owner}, {name})"] = offset
            layout[f"sizeof((({owner} *)0)->{name})"] = struct.calcsize(fmt)
    layout["sizeof(music_playlist_randomized_latch)"] = 1
    # These headers currently disagree on sfx_play return type; isolate its unused declaration.
    source = '#include "crimsonland_gameplay.h"\n#define sfx_play audio_sfx_play_declaration\n#include "crimsonland_audio.h"\n#undef sfx_play\n#include <stddef.h>\nextern "C" {\n'
    source += "unsigned int execution_offsets[] = {" + ", ".join(layout) + "};\n}\n"
    (directory / "scratch.cpp").write_text(source)
    path = match.compile_scratch(replace(config, directory=directory))
    obj = match.parse_coff_object(path.read_bytes())
    symbol = next(row for row in obj.symbols if row.name == "_execution_offsets")
    raw = obj.sections[symbol.section_number - 1].data[symbol.value : symbol.value + 4 * len(layout)]
    actual = struct.unpack("<" + "I" * len(layout), raw)
    assert list(actual) == list(layout.values()), dict(zip(layout, actual, strict=True))
    return layout


def fields(trace, category, index):
    from execute import CATEGORIES

    name = CATEGORIES[category]
    stride = POOLS[name][1]
    return {
        field: struct.unpack_from("<" + fmt, trace["state"][name], index * stride + offset)[0]
        for field, (offset, fmt) in F[category].items()
    }


def scenarios(p):
    f32 = m.f32
    rand = random.Random(2026091104)
    cases = []
    for i in range(1200):
        mode = i % 3
        style = (0, 1, 2, 8)[(i // 3) % 4]
        cw = 0x7F if (i // 12) % 2 else 0x37F
        index = rand.randrange(128)
        target = rand.randrange(384)
        dt = rand.uniform(0.001, 0.1)
        item = {
            "index": index,
            "style": style,
            "render": 1,
            "x": rand.uniform(-0.2, 0.2) if mode == 2 else rand.uniform(100, 900),
            "y": rand.uniform(-0.2, 0.2) if mode == 2 else rand.uniform(100, 900),
            "vx": rand.uniform(-100, 100),
            "vy": rand.uniform(-100, 100),
            "angle": rand.uniform(-13, 13),
            "spin": rand.uniform(-5, 5),
            "intensity": rand.uniform(0.91, 2.1),
            "target": -1,
        }
        case = {"fpcw": cw, "dt": dt, "rng_seed": rand.randrange(2**32), "particles": [item]}
        after = fields(run(p, True, case), "particles", index)
        if mode == 2 and style != 8:
            angle = after["angle"]
            tau = f32(2 * math.pi)
            while angle > tau:
                angle = f32(angle - tau)
            while angle < 0:
                angle = f32(angle + tau)
            distance = rand.uniform(0.2, 3)
            x = f32(after["x"] - f32(dt) * after["vx"] - distance * math.cos(angle))
            y = f32(after["y"] - f32(dt) * after["vy"] - distance * math.sin(angle))
        else:
            x = f32(after["x"] + rand.uniform(-2, 2))
            y = f32(after["y"] + rand.uniform(-2, 2))
        color = [f32(rand.uniform(0, 1)) for _ in range(4)]
        if mode == 1:
            color[0] = f32(rand.uniform(0.3, 0.8))
            color[1] = f32(rand.uniform(0.3, 0.8))
            color[2] = f32(f32(1.6) - f32(color[0] + color[1]))
            bits = struct.unpack("<I", struct.pack("<f", color[2]))[0]
            color[2] = struct.unpack("<f", struct.pack("<I", bits + rand.choice([-1, 0, 1])))[0]
        case["creatures"] = [
            {
                "index": target,
                "x": x,
                "y": y,
                "health": 100,
                "max_health": 100,
                "size": 42,
                "lifecycle": 16,
                "r": color[0],
                "g": color[1],
                "b": color[2],
                "a": color[3],
                "type": 0,
            },
        ]
        assert fields(run(p, True, case), "particles", index)["render"] == 0, (i, "unreachable collision")
        cases.append(case)
    for color, cw, seed in itertools.product(
        ((-0.1, 0.1, 0.1, 1.2), (1.2, 0.1, 0.1, -0.2), (-0.2, 1, 1, -0.2), (0.5, 0.5, 0.5, 1.2), (0, 0, 0, -0.1)),
        (0x7F, 0x37F),
        (0, 1, 2039877910),
    ):
        case = copy.deepcopy(cases[13])
        case["fpcw"] = cw
        case["rng_seed"] = seed
        for key, value in zip(("r", "g", "b", "a"), color, strict=True):
            case["creatures"][0][key] = value
        cases.append(case)
    return cases


def integrated_scenarios(cases):
    cases = [copy.deepcopy(case) for case in cases if case["fpcw"] == 0x7F]
    for style in (0, 1, 2, 8):
        base = next(
            case for case in cases if case["particles"][0]["style"] == style and case["particles"][0]["index"] % 3 == 0
        )
        for health, perks in itertools.product((100.0, 0.0, -10.0), ([], [39], [28, 29, 34], [28, 29, 34, 39])):
            case = copy.deepcopy(base)
            case["creatures"][0]["health"] = health
            case["perks"] = perks
            cases.append(case)
    assert len(cases) == 663
    return cases
