"""Stored-float frame boundaries and the recovered six-species atlas table."""

import itertools
import random
import struct

# gameplay_reset_state, plus the initially zeroed trooper frame/flag fields.
TYPE_INFO = ((32, 0), (16, 1), (32, 0), (16, 1), (16, 1), (0, 0))
FLAGS = (0, 4, 16, 20, 64, 68, 80, 84)


def f32(value):
    return struct.unpack("<f", struct.pack("<f", value))[0]


def neighbors(value):
    bits = struct.unpack("<I", struct.pack("<f", value))[0]
    assert value > 0
    return [struct.unpack("<f", struct.pack("<I", bits + delta))[0] for delta in (-1, 0, 1)]


def scenarios():
    rng = random.Random(2026091114)
    cases = []
    stages = [-10.0, -1.0, -0.0, 0.0, 0.00001, 0.5, 15.5, 20.0]
    for stage in (1.0, 7.0, 15.0, 16.0):
        stages.extend(neighbors(stage))
    phases = [-17.0, -1.0, -0.5, 0.0, 31.0]
    for phase in (0.5, 7.5, 15.5, 16.5, 23.5, 30.5):
        phases.extend(neighbors(phase))
    for type_id in range(6):
        families = {
            "lifecycle": [
                {"flags": flags, "lifecycle_stage": stage, "anim_phase": (4.2, 15.5, 23.5)[index % 3]}
                for index, (flags, stage) in enumerate(itertools.product(FLAGS, stages))
            ],
            "phase": [
                {"flags": flags, "lifecycle_stage": 20.0, "anim_phase": phase}
                for flags, phase in itertools.product(FLAGS, phases)
            ],
            "random": [
                {
                    "flags": rng.choice(FLAGS),
                    "lifecycle_stage": f32(rng.uniform(-9.0, 24.0)),
                    "anim_phase": f32(rng.uniform(-2.0, 32.0)),
                }
                for _ in range(96)
            ],
        }
        for family, records in families.items():
            assert len(records) < 384
            for index, record in enumerate(records):
                record.update(type_id=type_id, index=383 if index == len(records) - 1 else index)
                record["anim_phase"] = f32(record["anim_phase"])
            for fpcw in (0x7F, 0x37F):
                cases.append(
                    {
                        "name": f"{family}-type-{type_id}-cw-{fpcw:04x}",
                        "type_id": type_id,
                        "fpcw": fpcw,
                        "shadows": 1,
                        "flash": 1,
                        "energizer": 0.25 if family == "random" else 0.0,
                        "creatures": records,
                    },
                )
    return cases
