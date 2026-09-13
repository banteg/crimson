"""Secondary steering and trail witnesses at both x87 precision settings."""

import math
import random

import execute as engine


def steering_cases(mode, count):
    rng = random.Random(2026091321)
    for index in range(count):
        kind = (1, 4, 2)[index // 2 % 3]
        threshold = 500 if kind == 1 else 600 if kind == 4 else 350
        angle = rng.uniform(-math.pi, math.pi)
        speed = threshold * (1 + rng.uniform(-0.015, 0.015)) if index // 6 % 2 else rng.uniform(0, 1000)
        case = {
            "fpcw": (0x7F, 0x37F)[index % 2],
            "dt": engine.m.f32(rng.uniform(0.0001, 0.08)),
            "rng_seed": rng.randrange(2**32),
            "secondary": [
                {
                    "index": index % 64,
                    "type": kind,
                    "x": 400.0,
                    "y": 400.0,
                    "vx": engine.m.f32(math.cos(angle) * speed),
                    "vy": engine.m.f32(math.sin(angle) * speed),
                    "life": 1.0,
                    "trail": 0.0 if mode == "trail" else 1.0,
                    "angle": engine.m.f32(rng.uniform(-7, 7)),
                    "target": index % 384,
                },
            ],
        }
        if kind == 2:
            case["creatures"] = [
                {
                    "index": index % 384,
                    "x": 850.0,
                    "y": 850.0,
                    "health": 1000.0,
                    "max_health": 1000.0,
                    "size": 50.0,
                    "lifecycle": 16.0,
                },
            ]
        yield case
