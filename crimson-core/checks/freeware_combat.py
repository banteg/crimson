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
from types import SimpleNamespace

from crimson_re.dbg.native_oracle import NativeOracle, SymbolTable

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "crimson-core"))
from freeware.build import game_flags, game_sources

# symbol, original VA, record format (preserves the exact x86 padding), capacity
BULLET = ("projectile_pool", 0x439260, "<B3x7fi4f", 64)
ROCKET = ("secondary_projectile_pool", 0x43BB78, "<B3x6fifi", 64)
PARTICLE = ("particle_pool", 0x439F60, "<BB2x11fB3xi", 128)
SPRITE = ("sprite_effect_pool", 0x43CBC8, "<B3x10f", 384)
CREATURE = ("creature_pool", 0x442AF8, "<BB2xffB3x14fB3x5fd12xiif", 512)


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
    def __init__(self, dll, exe, symbol):
        self.dll = dll
        self.symbol = symbol
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
        pe.write_u32(0x43C5C8, 6)
        pe.write_u32(0x4385D4, 2)
        self.keys = 0
        for offset, fn in [
            (0x40, lambda call: (self.keys << 8) >> (call.arg_u32(0) & 31) & 1),
            (0x44, 0),
            (0x48, 0),
            (0x4C, 0),
        ]:
            address = pe.load_code(b"\xc3")
            pe.stub(address, fn, pop=4)
            pe.write_u32(table + offset, address)
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
        return ctypes.c_int.from_address(self.symbol(name))

    def address(self, pool):
        return self.symbol(pool[0])

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
                    ctypes.c_float.from_address(self.symbol("bonus_fire_bullets_timer")).value = 2
                self.write(
                    BULLET,
                    slot,
                    struct.pack(BULLET[2], 1, angle, x, 500, x, 500, 1, 2, kind, 0.4, 1, 1.07, pool),
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

    def actors(self, mode, perk, partner, shield):
        self.dll.combat_actors(mode, perk, partner, shield)
        pe = self.pe
        pe.write_u32(0x4428A8, mode)
        pe.write_u32(0x4428A0, 2)
        pe.write_u32(0x43850C + perk * 4, 1)
        pe.write_u8(0x438484, perk == 10)
        pe.write_f32(0x4385F0, shield)
        for i, (x, health) in enumerate([(500, 0 if partner else 100), (600, 100)]):
            for va, value in [(0x438490, x), (0x438494, 500), (0x4384A0, health)]:
                pe.write_f32(va + i * 392, value)

    def creatures(self):
        pe = self.pe
        for scenario in (
            "pursuit",
            "melee",
            "shield",
            "invisible",
            "plague",
            "radioactive",
            "inactive",
            "dead",
            "child",
            "retarget",
            "suicide",
            "freeze",
        ):
            self.reset(187)
            perk = {"radioactive": 12, "invisible": 2, "melee": 10}.get(scenario, 0)
            self.actors(1, perk, scenario == "retarget", float(scenario == "shield"))
            for va, v in [(0x452DE8, 2), (0x452E10, 12), (0x452DB4, 1)]:
                pe.write_u8(va, v)
            data = creature(
                517 if scenario in ("melee", "shield", "suicide", "radioactive") else 420,
                500,
                7 if scenario in ("plague", "radioactive") else 90,
            )
            for off, v in [(44, 1.3), (80, 0), (84, 7), (88, 1.65), (92, 0), (124, 30.8)]:
                struct.pack_into("<f", data, off, v)
            if scenario == "plague":
                data[12] = 1
            if scenario == "dead":
                struct.pack_into("<f", data, 20, 8)
            if scenario == "child":
                struct.pack_into("<f", data, 8, 3.98)
            if scenario == "suicide":
                struct.pack_into("<f", data, 52, 29)
            if scenario == "inactive":
                data[1] = 0
            self.write(CREATURE, 0, data)
            self.write(CREATURE, 1, creature(450, 500, 120))
            ctypes.c_float.from_address(self.symbol("freeware_elapsed_seconds")).value = 0
            for i in range(6):
                clock = 0.5 + i * 0.05
                pe.write_f32(0x452E94, 0.05)
                pe.write_f32(0x452D40, clock)
                ice = float(scenario == "freeze")
                pe.write_f32(0x452DBC, ice)
                pe.call(0x40D8C0)
                self.dll.combat_creatures(0.05, clock, ice)
                for j in range(3):
                    self.compare(CREATURE, j, (scenario, i))
                for j in range(2):
                    player = self.address(("player_state_table",))
                    health = ctypes.c_float.from_address(player + 392 * j + 40).value
                    assert math.isclose(health, pe.read_f32(0x4384A0 + j * 392), abs_tol=0.0001), (scenario, i, health)
                assert self.dll.combat_experience() == pe.read_i32(0x4384F8), (scenario, i, "XP")
                self.frames += 1
            assert self.pe.call(0x422414).eax == self.dll.crt_rand(), (scenario, "next rand")

    def rewards(self):
        for seed in range(24):
            self.reset(seed)
            self.actors(1, seed % 2, False, 0)
            pe = self.pe
            pe.write_u32(0x4385D4, 2)  # Survival reset gives the port an AutoRifle.
            pe.write_u32(0x43C5C8, 6)
            pe.write_u32(0x452E60, 99)
            pe.write_u32(0x4387E8, 99)
            for j in range(6):
                pe.write_u32(0x42FBBC + 4 * j, j)
            data = creature(650, 500, 0)
            self.write(CREATURE, 0, data)
            dt = 0.032
            ice = 1 if seed % 3 == 0 else 0
            pe.write_f32(0x452E94, dt)
            pe.write_f32(0x452DBC, ice)
            corpse = bool(seed % 2)
            pe.call(0x405E10, 0, 0, corpse)
            self.dll.combat_reward(dt, ice, corpse)
            self.compare(CREATURE, 0, ("reward", seed))
            self.compare(SPRITE, 0, ("reward", seed))
            assert self.dll.combat_first_xp() == pe.read_i32(0x452D80)
            assert self.dll.combat_experience() == pe.read_i32(0x4384F8)
            pickup = pe.read_i32(0x4387E8)
            assert self.dll.combat_drop() == (-1 if pickup == 99 else pickup)
            if pickup == 2:
                assert self.dll.combat_drop_weapon() == pe.read_i32(0x452E68)
            assert self.pe.call(0x422414).eax == self.dll.crt_rand(), ("reward", seed, "next rand")

    def grants(self):
        pe = self.pe

        def read_string(pointer):
            return pe.read(pointer, 1024).split(b"\x00", 1)[0]

        def duplicate(call):
            raw = read_string(call.arg_u32(0)) + b"\x00"
            return pe.alloc(len(raw), data=raw)

        pe.stub(0x42C2EC, duplicate)
        pe.stub(0x421B81, 0)
        for seed in (1, 42):
            for perk in range(1, 33):
                self.reset(seed)
                pe.stub(0x4078B0, lambda call: call.arg_u32(0))
                pe.call(0x407920)  # Native registration binds the perk IDs.
                pe.write_u32(0x452DA8, perk)
                pe.write_u32(0x452E70, 2)
                pe.write_u32(0x438500, 1)
                pe.write_f32(0x4384A0, 100)
                pe.write_f32(0x4385DC, 30)
                message = []
                pe.stub(
                    0x4078B0,
                    lambda call, message=message: message.append(read_string(call.arg_u32(0)).decode("ascii")) or 0,
                )
                pe.rand_state = seed
                # Accepted mouse click, through the native co-op copy at the common exit.
                pe.run(0x415DD7, 0x416551, regs={"ebp": 0, "ebx": 2})
                self.dll.combat_choose(perk)
                assert self.dll.combat_experience() == pe.read_i32(0x4384F8)
                assert self.dll.combat_health() == pe.read_f32(0x4384A0)
                assert self.dll.combat_pending() == pe.read_i32(0x452E70)
                assert self.dll.combat_level() == pe.read_i32(0x438500)
                player = self.address(("player_state_table",))
                assert ctypes.c_int.from_address(player + 0x15C).value == pe.read_i32(0x4385D4), (
                    perk,
                    seed,
                    ctypes.c_int.from_address(player + 0x15C).value,
                    pe.read_i32(0x4385D4),
                )
                assert ctypes.c_float.from_address(player + 0x164).value == pe.read_f32(0x4385DC)
                for j in range(2):
                    assert ctypes.string_at(player + 392 * j + 0x94, 192) == pe.read(0x43850C + 392 * j, 192)
                assert ctypes.c_uint8.from_address(player + 12).value == pe.read_u8(0x438484)
                assert self.dll.combat_message().decode() == (message[0] if message else ""), (
                    perk,
                    seed,
                    self.dll.combat_message(),
                    message,
                )
                assert self.pe.call(0x422414).eax == self.dll.crt_rand(), ("perk", perk, seed)

    def players(self):
        pe = self.pe
        for weapon in range(1, 21):
            self.reset(42)
            self.dll.combat_arm(weapon)
            for va, value in [
                (0x4428A8, 1),
                (0x4428A0, 1),
                (0x4428AC, 2),
                (0x4428B4, 0),
                (0x4385D4, weapon),
                (0x452DDC, 3),
                (0x452DE0, 8),
                (0x452DE4, 14),
                (0x452E14, 11),
                (0x452DEC, 4),
                (0x452DE8, 2),
                (0x452E24, 22),
                (0x452DFC, 7),
                (0x452E1C, 18),
            ]:
                pe.write_u32(va, value)
            for va, value in [
                (0x42FB8C, 1),
                (0x452DC4, 7),
                (0x438490, 512),
                (0x438494, 512),
                (0x4384A0, 4),
                (0x4384AC, 48),
                (0x4385CC, 1),
                (0x4384D0, 2),
                (0x4384E4, 10),
                (0x4385DC, 10),
                (0x438508, 1),
            ]:
                pe.write_f32(va, value)
            for va in (0x452D59, 0x4428F4, 0x452D4D):
                pe.write_u8(va, 1)
            # The port uses the platform's scancodes. Give the original five distinct bits for the same keys.
            for offset, bit in [(0, 4), (1, 2), (2, 3), (3, 1), (4, 0)]:
                pe.write_u8(0x4385F4 + offset, 8 + bit)
            for j in range(4):
                pe.write_u8(0x43877C + j, 24)
            for i, (keys, x, y) in enumerate(
                [(1, 712, 512), (2, 514, 774), (6, 391, 514), (16, 620, 477), (0, 712, 514), (9, 600, 520)],
            ):
                self.keys = keys
                dt = 0.017
                pe.write_f32(0x438800, x)
                pe.write_f32(0x438804, y)
                pe.write_f32(0x452E94, dt)
                pe.call(0x4126E0)
                self.dll.combat_player(dt, keys, x, y)
                player = self.address(("player_state_table",))
                for offset in (0x18, 0x1C, 0x4C, 0x50, 0x6C, 0x8C, 0x154, 0x168, 0x16C):
                    expected = pe.read_f32(0x438478 + offset)
                    got = ctypes.c_float.from_address(player + offset).value
                    assert math.isclose(got, expected, abs_tol=0.001), (weapon, i, hex(offset), got, expected)
                for pool, count in [(BULLET, 16), (ROCKET, 2), (PARTICLE, 5), (SPRITE, 5)]:
                    for slot in range(count):
                        self.compare(pool, slot, ("player", weapon, i))
                self.frames += 1
            assert pe.call(0x422414).eax == self.dll.crt_rand(), ("player", weapon, "next rand")


def check_client(dll, exe, address, target):
    comparison = Comparison(dll, exe, address)
    comparison.grants()
    comparison.players()
    comparison.creatures()
    comparison.rewards()
    comparison.projectiles()
    print(
        f"1.4.0 {target} combat oracle passed {comparison.frames} frames, 24 reward rolls and 64 perk grants.",
        flush=True,
    )


def check_web(stage, exe, sources):
    # Emscripten builds the same translation units as the browser. WASI supplies stdio to the test host.
    import wasmtime

    compiler = shutil.which("em++")
    if not compiler:
        raise SystemExit("em++ is required for --web")
    functions = (
        "combat_reset",
        "combat_projectiles",
        "combat_creatures",
        "combat_actors",
        "combat_reward",
        "combat_player",
        "combat_arm",
        "combat_choose",
        "combat_message",
        "combat_health",
        "combat_level",
        "combat_pending",
        "combat_drop",
        "combat_drop_weapon",
        "combat_first_xp",
        "combat_experience",
        "crt_rand",
    )
    data = [p[0] for p in (CREATURE, BULLET, ROCKET, PARTICLE, SPRITE)] + [
        "bonus_fire_bullets_timer",
        "freeware_elapsed_seconds",
        "player_state_table",
        "creature_spawned_count",
        "highscore_record_hits",
    ]
    out = stage / "combat.wasm"
    subprocess.run(
        [
            compiler,
            *game_flags(ROOT),
            *sources,
            "--no-entry",
            "-sSTANDALONE_WASM",
            *("-Wl,--export=" + name for name in (*functions, *data)),
            "-o",
            out,
        ],
        check=True,
    )
    engine = wasmtime.Engine()
    store = wasmtime.Store(engine)
    store.set_wasi(wasmtime.WasiConfig())
    linker = wasmtime.Linker(engine)
    linker.define_wasi()
    exports = linker.instantiate(store, wasmtime.Module.from_file(engine, str(out))).exports(store)
    exports["_initialize"](store)
    memory = exports["memory"]

    def pointer(offset):
        return ctypes.addressof(memory.data_ptr(store).contents) + offset

    def function(name):
        fn = exports[name]
        if name == "combat_message":
            return lambda: ctypes.string_at(pointer(fn(store)))
        converters = [float if str(param) in {"f32","f64"} else int for param in fn.type(store).params]
        return lambda *args: fn(store, *(cast(arg) for cast,arg in zip(converters,args,strict=True)))

    exports_host = SimpleNamespace(**{name: function(name) for name in functions})
    check_client(exports_host, exe, lambda name: pointer(exports[name].value(store)), "WebAssembly")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("install", type=Path)
    p.add_argument("--web", action="store_true", help="also compare Emscripten output (requires wasmtime)")
    args = p.parse_args()
    exe = args.install / "crimson.exe"
    spec = next(b for b in json.loads((ROOT / "decomp/builds.json").read_text())["builds"] if b["id"] == "1.4.0")
    assert hashlib.sha256(exe.read_bytes()).hexdigest() == next(
        i["sha256"] for i in spec["images"] if i["name"] == "crimson.exe"
    )
    with tempfile.TemporaryDirectory() as tmp:
        stage = Path(tmp)
        sources = [*game_sources(ROOT, stage), ROOT / "crimson-core/checks/freeware_combat.cpp"]
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
                *sources,
                "-o",
                lib,
            ],
            check=True,
        )
        dll = ctypes.CDLL(str(lib))
        dll.combat_projectiles.argtypes = [ctypes.c_float] * 3
        dll.combat_creatures.argtypes = [ctypes.c_float] * 3
        dll.combat_actors.argtypes = [ctypes.c_int] * 3 + [ctypes.c_float]
        dll.combat_reward.argtypes = [ctypes.c_float, ctypes.c_float, ctypes.c_bool]
        dll.combat_player.argtypes = [ctypes.c_float, ctypes.c_int, ctypes.c_float, ctypes.c_float]
        dll.combat_message.restype = ctypes.c_char_p
        dll.combat_health.restype = ctypes.c_float
        check_client(dll, exe, lambda name: ctypes.addressof(ctypes.c_char.in_dll(dll, name)), "native")
        if args.web:
            check_web(stage, exe, sources)


if __name__ == "__main__":
    main()
