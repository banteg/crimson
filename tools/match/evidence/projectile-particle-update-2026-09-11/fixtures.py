"""Deterministic no-hit trajectories and compiler-checked field layouts."""

import itertools
import random
import struct
from dataclasses import replace

from execute import POOLS, F, match


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


def particle(rand, index, style, render, intensity):
    return {
        "index": index,
        "style": style,
        "intensity": intensity,
        "render": render,
        "x": rand.uniform(-10, 1000),
        "y": rand.uniform(-10, 1000),
        "vx": rand.uniform(-100, 100),
        "vy": rand.uniform(-100, 100),
        "angle": rand.uniform(-7, 7),
        "spin": rand.uniform(-7, 7),
        "target": -1,
    }


def scenarios():
    cases = [{}]
    for typ, life, dt, cw, ion in itertools.product(
        (1, 2, 7, 9, 21, 22, 23, 24, 28, 41),
        (-0.1, 0, 0.001, 0.39, 0.4, 0.41),
        (0.001, 0.016, 0.1),
        (0x7F, 0x37F),
        (0, 1),
    ):
        cases.append(
            {
                "primary": [
                    {"type": typ, "life": life, "x": 100, "y": 300, "owner": -1, "speed": 1, "radius": 1, "travel": 0},
                ],
                "dt": dt,
                "fpcw": cw,
                "perks": [1] if ion else [],
                "shock_id": 0,
            },
        )
    rand = random.Random(20260911)
    for i in range(800):
        cases.append(
            {
                "fpcw": 0x7F if i % 2 else 0x37F,
                "dt": rand.uniform(0.001, 0.1),
                "perks": [2] if i % 3 else [],
                "primary": [
                    {
                        "index": rand.randrange(96),
                        "type": rand.choice([1, 2, 7, 9, 21, 22, 23, 24, 28, 41]),
                        "life": 0.5,
                        "x": rand.uniform(10, 950),
                        "y": rand.uniform(10, 950),
                        "angle": rand.uniform(-7, 7),
                        "owner": -1,
                        "speed": rand.uniform(0.25, 5),
                        "radius": rand.uniform(1, 8),
                        "travel": rand.randrange(1, 40),
                    },
                ],
            },
        )
    original_particles = []
    for i in range(800):
        dt = rand.uniform(0.001, 0.1)
        item = particle(
            rand,
            rand.randrange(128),
            rand.choice([0, 1, 3, 8]),
            i % 2,
            rand.choice([0.001, 0.14, 0.15, 0.16, 0.7, 0.79, 0.8, 0.81, 1, 1.2, 2.1]),
        )
        original_particles.append({"fpcw": 0x7F if i % 2 else 0x37F, "dt": dt, "particles": [item]})
    cases.extend(original_particles)
    for i in range(400):
        cases.append(
            {
                "fpcw": 0x7F if i % 2 else 0x37F,
                "dt": rand.uniform(0.001, 0.1),
                "sprites": [
                    {
                        "index": rand.randrange(384),
                        "alpha": rand.uniform(-0.1, 1.1),
                        "rotation": rand.uniform(-7, 7),
                        "x": rand.uniform(-10, 1000),
                        "y": rand.uniform(-10, 1000),
                        "vx": rand.uniform(-100, 100),
                        "vy": rand.uniform(-100, 100),
                        "scale": rand.uniform(1, 90),
                    },
                ],
            },
        )
    for i in range(400):
        cases.append(
            {
                "fpcw": 0x7F if i % 2 else 0x37F,
                "dt": rand.uniform(0.001, 0.1),
                "secondary": [
                    {
                        "index": rand.randrange(64),
                        "type": rand.choice([1, 3, 4]),
                        "angle": rand.uniform(-7, 7),
                        "life": rand.uniform(-0.1, 2),
                        "x": rand.uniform(-10, 1000),
                        "y": rand.uniform(-10, 1000),
                        "vx": rand.uniform(-500, 500),
                        "vy": rand.uniform(-500, 500),
                        "trail": 30,
                        "target": -1,
                    },
                ],
            },
        )
    cases.extend(dict(case, fpcw=0x37F if case["fpcw"] == 0x7F else 0x7F) for case in original_particles)
    # Independently cross every control: no precision/render correlation.
    for style, render, cw, intensity, dt in itertools.product(
        (0, 1, 2, 8),
        (0, 1),
        (0x7F, 0x37F),
        (-0.1, 0, 0.001, 0.14, 0.15, 0.16, 0.79, 0.8, 0.81, 1, 1.2, 2.1),
        (1e-20, 0.016, 0.1, 1.0),
    ):
        cases.append(
            {
                "fpcw": cw,
                "dt": dt,
                "rng_seed": rand.randrange(2**32),
                "particles": [particle(rand, rand.randrange(128), style, render, intensity)],
            },
        )
    for i in range(128):
        items = [
            particle(rand, index, rand.choice((0, 1, 2, 8)), rand.randrange(2), rand.uniform(0.05, 2.1))
            for index in rand.sample(range(128), 12)
        ]
        cases.append(
            {
                "fpcw": 0x7F if i % 2 else 0x37F,
                "dt": rand.uniform(0.001, 0.1),
                "rng_seed": rand.randrange(2**32),
                "particles": items,
            },
        )
    return cases
