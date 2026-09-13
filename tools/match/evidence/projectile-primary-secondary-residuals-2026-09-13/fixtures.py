"""Weapon and explosion cases targeting recovered expression boundaries."""

import math
import random
import struct

import execute as engine


def next32(x, step):
    bits = struct.unpack("<I", struct.pack("<f", x))[0]
    return struct.unpack("<f", struct.pack("<I", bits + step))[0]


def scenarios(program, suite, count):
    rng = random.Random(2026091320)
    for i in range(count):
        case = {
            "fpcw": (0x7F, 0x37F)[i % 2],
            "dt": engine.m.f32(rng.uniform(0.001, 0.05)),
            "rng_seed": rng.randrange(2**32),
            "violence_disabled": 1,
        }
        if suite == "primary-weapons":
            types = (1, 6, 19, 21, 22, 23, 24, 25, 28, 41, 45, 29)
            kind = types[(i // 2) % len(types)]
            case.update(perks=[1] if i // 24 % 2 else [], freeze=float(i // 48 % 2), shock_id=i % 96, shock_links=3)
            projectile = {
                "index": i % 96,
                "type": kind,
                "angle": engine.m.f32(rng.uniform(-7, 7)),
                "x": engine.m.f32(rng.uniform(50, 900)),
                "y": engine.m.f32(rng.uniform(50, 900)),
                "origin_x": 30,
                "origin_y": 20,
                "life": 1,
                "speed": engine.m.f32(rng.uniform(0.1, 5)),
                "radius": 1,
                "travel": 3,
                "damage": (0.25, 1, 2)[i // 96 % 3],
                "owner": -100,
            }
            case["primary"] = [projectile]
            pre = engine.run(program, True, case)
            query = next(c for c in pre["calls"] if c[0] == "creature_find_in_radius")
            x, y = struct.unpack("<2f", struct.pack("<2I", *query[1]))
            case["creatures"] = [
                {"index": i % 384, "x": x, "y": y, "health": 1000, "max_health": 1000, "size": 50, "lifecycle": 16},
                {
                    "index": (i + 1) % 384,
                    "x": x + 60,
                    "y": y + 60,
                    "health": 1000,
                    "max_health": 1000,
                    "size": 50,
                    "lifecycle": 16,
                },
            ]
        elif suite == "explosion":
            scale = engine.m.f32(rng.uniform(0.2, 1))
            progress = engine.m.f32(rng.uniform(0.1, 0.7))
            px = engine.m.f32(rng.uniform(100, 900))
            py = engine.m.f32(rng.uniform(100, 900))
            radius = engine.m.f32(scale * engine.m.f32(progress + case["dt"] * 3) * 80)
            case["secondary"] = [{"index": i % 64, "type": 3, "x": px, "y": py, "vx": progress, "vy": scale, "life": 1}]
            case["creatures"] = []
            for j in range(5):
                angle = rng.uniform(-3, 3)
                r = radius * (1 if j < 3 else (0.5 if j == 3 else 1.5))
                x = next32(px + math.cos(angle) * r, j - 1 if j < 3 else 0)
                y = engine.m.f32(py + math.sin(angle) * r)
                creature = {
                    "index": (i * 5 + j) % 384,
                    "x": x,
                    "y": y,
                    "health": 1000,
                    "max_health": 1000,
                    "size": 50,
                    "lifecycle": 16,
                }
                case["creatures"].append(creature)
        else:
            raise ValueError(suite)
        yield case


def rocket_cases(program, count):
    rng = random.Random(2026091319)
    for i in range(count):
        case = {
            "fpcw": 0x7F if i % 2 == 0 else 0x37F,
            "dt": engine.m.f32(rng.uniform(0.001, 0.1)),
            "rng_seed": rng.randrange(2**32),
        }
        secondary = {
            "index": i % 64,
            "type": (1, 4)[i // 2 % 2],
            "x": engine.m.f32(rng.uniform(100, 900)),
            "y": engine.m.f32(rng.uniform(100, 900)),
            "vx": 20.0,
            "vy": 10.0,
            "life": 1.0,
            "trail": 1.0,
            "angle": engine.m.f32(rng.uniform(-7, 7)),
        }
        case["secondary"] = [secondary]
        pre = engine.run(program, True, case)
        query = next(call for call in pre["calls"] if call[0] == "creature_find_in_radius")
        x, y = struct.unpack("<2f", struct.pack("<2I", *query[1]))
        creature = {"index": i % 384, "x": x, "y": y, "health": 1000, "max_health": 1000, "size": 50, "lifecycle": 16}
        case["creatures"] = [creature]
        yield case
