"""Compare a particle runtime update with an independently recorded native witness."""

import struct

from crimson.effects import ParticlePool, ParticleStyleId
from crimson.math_parity import f32
from grim.geom import Vec2
from grim.rand import Crand, RecordingCrand
from tests.support.factories import RecordingCreatureDamageRuntime
from tests.support.helpers import ScriptedCrand


def compare(witness):
    case = witness["input"]
    assert case.get("fpcw", 0x7F) == 0x7F
    rng = (
        RecordingCrand(Crand(case["rng_seed"]))
        if "rng_seed" in case
        else ScriptedCrand(witness["draws"] or [0], fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    )
    pool = ParticlePool(rng=rng)
    for item in case["particles"]:
        entry = pool.entries[item["index"]]
        entry.active = True
        entry.render_flag = bool(item["render"])
        entry.pos = Vec2(f32(item["x"]), f32(item["y"]))
        entry.vel = Vec2(f32(item["vx"]), f32(item["vy"]))
        entry.style_id = ParticleStyleId(item["style"])
        entry.target_id = item["target"]
        entry.scale_x = entry.scale_y = entry.scale_z = entry.age = 0.0
        for key in ("intensity", "angle", "spin"):
            setattr(entry, key, f32(item[key]))
    pool.update(case["dt"], creatures=(), creature_damage_runtime=RecordingCreatureDamageRuntime(creatures=()))
    for native in witness["particles"]:
        entry = pool.entries[native["index"]]
        values = {
            "active": int(entry.active),
            "render": int(entry.render_flag),
            "x": entry.pos.x,
            "y": entry.pos.y,
            "vx": entry.vel.x,
            "vy": entry.vel.y,
            "sx": entry.scale_x,
            "sy": entry.scale_y,
            "sz": entry.scale_z,
            "age": entry.age,
            "intensity": entry.intensity,
            "angle": entry.angle,
            "spin": entry.spin,
            "style": int(entry.style_id),
            "target": entry.target_id,
        }
        for key, value in values.items():
            if key in ("active", "render", "style", "target"):
                assert value == native[key], (witness["index"], key, value, native[key])
            else:
                assert struct.pack("<f", value) == struct.pack("<f", native[key]), (
                    witness["index"],
                    key,
                    value,
                    native[key],
                )
    records = rng.records_since()
    assert [record.value for record in records] == witness["draws"], witness["index"]
    assert [record.caller for record in records] == witness["rng_callers"], witness["index"]
    if "rng_seed" in case:
        assert rng.state == witness["rng_state"], witness["index"]


