"""Compare shared freeware combat code with the original x86 routines, one frame at a time."""

import argparse
import ctypes
import hashlib
import json
import math
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from crimson_re.dbg.native_oracle import NativeOracle, SymbolTable

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "crimson-core"))
from freeware.build import game_flags, game_sources

# symbol, original VA, record format (preserves the exact x86 padding), capacity
BULLET = ("projectile_pool", 0x439260, "<B3x7fi4f", 64)
ROCKET = ("secondary_projectile_pool", 0x43BB78, "<B3x6fifi", 64)
PARTICLE = ("particle_pool", 0x439F60, "<BB2x11fB3xi", 128)
SPRITE = ("sprite_effect_pool", 0x43CBC8, "<B3x10f", 384)
CREATURE = ("creature_pool", 0x442AF8, "<BB2xffB3x14fB3x5fd2f2i2f", 512)


def creature(x, y, health):
    data = bytearray(128)
    struct.pack_into("<BB", data, 0, 1, 1)
    for off, value in [
        (8, -1),
        (20, 16),
        (24, x),
        (28, y),
        (40, health),
        (52, 49),
        (56, 0.8),
        (60, 0.7),
        (64, 0.6),
        (68, 1),
    ]:
        struct.pack_into("<f", data, off, value)
    struct.pack_into("<d", data, 96, 103.8)
    return data


class Comparison:
    def __init__(self, dll, exe):
        self.dll = dll
        self.pe = pe = NativeOracle(exe, symbols=SymbolTable({}), rand_state_address=0x432C40)
        # Keep collision, damage, sound choices, death, drop rolls and the RNG running in the PE.
        # Stub only sound playback, texture lookup and the render queue.
        for address in (0x405630, 0x405760, 0x405C80):
            pe.stub(address, 0)
        table = pe.alloc(256)
        pe.write_u32(0x452D94, pe.alloc(4, data=struct.pack("<I", table)))
        lookup = pe.load_code(b"\xc3")
        pe.stub(lookup, 0, pop=4)
        pe.write_u32(table + 0x90, lookup)
        pe.write_u32(0x43CBB8, pe.alloc(0x80))
        for va, v in [(0x4428A8, 2), (0x4428A0, 1), (0x42FBD8, 1024), (0x42FBDC, 1024), (0x452DD8, 1)]:
            pe.write_u32(va, v)
        self.initial = pe.snapshot()
        self.frames = 0

    def reset(self, seed):
        self.pe.restore(self.initial)
        self.dll.combat_reset(seed)
        self.pe.rand_state = seed
        for pool in (CREATURE, BULLET, ROCKET, PARTICLE, SPRITE):
            data = bytes(struct.calcsize(pool[2]) * pool[3])
            self.write(pool, 0, data)
        self.dll_globals("creature_spawned_count").value = 0

    def dll_globals(self, name):
        return ctypes.c_int.in_dll(self.dll, name)

    def address(self, pool):
        return ctypes.addressof(ctypes.c_char.in_dll(self.dll, pool[0]))

    def write(self, pool, slot, data):
        offset = struct.calcsize(pool[2]) * slot
        self.pe.write(pool[1] + offset, bytes(data))
        ctypes.memmove(self.address(pool) + offset, bytes(data), len(data))

    def compare(self, pool, slot, label):
        fmt = pool[2]
        size = struct.calcsize(fmt)
        offset = size * slot
        orig = struct.unpack(fmt, self.pe.read(pool[1] + offset, size))
        port = struct.unpack(fmt, ctypes.string_at(self.address(pool) + offset, size))
        for field, (a, b) in enumerate(zip(orig, port, strict=True)):
            assert math.isclose(a, b, abs_tol=0.001, rel_tol=0.000002) if isinstance(a, float) else a == b, (
                label,
                pool[0],
                slot,
                field,
                a,
                b,
            )

    def projectile_frames(self, label, pool, slot, frames, dt, freeze=0):
        for i in range(frames):
            clock = 0.87 + (i + 1) * dt
            self.pe.write_f32(0x452E94, dt)
            self.pe.write_f32(0x452D40, clock)
            self.pe.write_f32(0x452DBC, freeze)
            self.pe.call(0x4094E0)
            self.dll.combat_projectiles(dt, clock, freeze)
            frame = (label, i + 1)
            self.compare(pool, slot, frame)
            for j in range(2):
                self.compare(CREATURE, j, frame)
            for j in (0, 1, 9):
                self.compare(SPRITE, j, frame)
            for va, name in [(0x4387F4, "highscore_record_hits"), (0x452E78, "creature_spawned_count")]:
                assert self.pe.read_i32(va) == self.dll_globals(name).value, (
                    frame,
                    name,
                    self.pe.read_i32(va),
                    self.dll_globals(name).value,
                )
            assert self.pe.read_i32(0x4384F8) == self.dll.combat_experience(), frame
            self.frames += 1
        assert self.pe.call(0x422414).eax == self.dll.crt_rand(), (label, "next rand")

    def projectiles(self):
        for kind in (1, 2, 4, 7, 9, 10, 17, 18):
            for scenario in ("flight", "impact", "kill", "edge", "fire"):
                self.reset(814)
                x = 1032 if scenario == "edge" else 500
                slot = 5 if kind == 18 else 0
                angle = 0.93 if scenario == "flight" else 1.57079637
                pool = 300 if kind == 10 else 240 if scenario == "fire" else 1
                if scenario == "fire":
                    self.pe.write_f32(0x452DB8, 2)
                    ctypes.c_float.in_dll(self.dll, "bonus_fire_bullets_timer").value = 2
                self.write(
                    BULLET, slot, struct.pack(BULLET[2], 1, angle, x, 500, x, 500, 1, 2, kind, 0.4, 1, 1.07, pool),
                )
                if scenario in ("impact", "kill", "fire"):
                    self.write(CREATURE, 0, creature(510, 500, 1000 if scenario == "impact" else 9))
                    self.write(CREATURE, 1, creature(525, 500, 75))
                self.projectile_frames((kind, scenario), BULLET, slot, 4, 0.02 if scenario == "flight" else 0.035)
        for kind in (1, 2):
            for scenario in ("flight", "impact", "kill", "timeout"):
                self.reset(71)
                self.write(
                    ROCKET,
                    0,
                    struct.pack(ROCKET[2], 1, 1.1, 0.06 if scenario == "timeout" else 2, 400, 400, 94, 12, kind, 0, 0),
                )
                self.write(
                    CREATURE,
                    1,
                    creature(415 if scenario in ("impact", "kill") else 680, 401, 24 if scenario == "kill" else 850),
                )
                self.projectile_frames(("rocket", kind, scenario), ROCKET, 0, 8, 0.04)
        for style in (0, 1, 8):
            for scenario in ("flight", "impact", "kill", "expire"):
                self.reset(523)
                self.write(
                    PARTICLE,
                    0,
                    struct.pack(
                        PARTICLE[2],
                        1,
                        1,
                        500,
                        500,
                        70,
                        5,
                        1,
                        1,
                        1,
                        1,
                        0.81 if scenario == "expire" else 1.0,
                        0.07,
                        2,
                        style,
                        -1,
                    ),
                )
                if scenario != "flight":
                    self.write(CREATURE, 0, creature(512, 500, 5 if scenario == "kill" else 100))
                self.projectile_frames(("particle", style, scenario), PARTICLE, 0, 8, 0.05)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("install", type=Path)
    args = p.parse_args()
    exe = args.install / "crimson.exe"
    spec = next(b for b in json.loads((ROOT / "decomp/builds.json").read_text())["builds"] if b["id"] == "1.4.0")
    assert hashlib.sha256(exe.read_bytes()).hexdigest() == next(
        i["sha256"] for i in spec["images"] if i["name"] == "crimson.exe"
    )
    with tempfile.TemporaryDirectory() as tmp:
        stage = Path(tmp)
        lib = stage / "combat.so"
        compiler = shutil.which("clang++")
        if not compiler:
            raise SystemExit("clang++ is required")
        subprocess.run(
            [
                compiler,
                *game_flags(ROOT),
                "-shared",
                "-fPIC",
                "-Wno-deprecated-declarations",
                *game_sources(ROOT, stage),
                ROOT / "crimson-core/checks/freeware_combat.cpp",
                "-o",
                lib,
            ],
            check=True,
        )
        dll = ctypes.CDLL(str(lib))
        dll.combat_projectiles.argtypes = [ctypes.c_float] * 3
        comparison = Comparison(dll, exe)
        comparison.projectiles()
        print(f"1.4.0 combat oracle passed {comparison.frames} frames.")


if __name__ == "__main__":
    main()
