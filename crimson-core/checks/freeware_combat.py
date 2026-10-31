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
from freeware_frame_cases import check_frames
from freeware_player_cases import check_controls

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
        pe.write_u32(0x452EA0, pe.alloc(0x30))  # Inactive music buffer, including its native thiscall returns.
        for address in (0x405630, 0x405C80):
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

    def projectile_frames(self, label, pool, slot, frames, dt, freeze=0, fragments=0):
        for i in range(frames):
            clock = 0.87 + (i + 1) * dt
            self.pe.write_f32(0x452E94, dt)
            self.pe.write_f32(0x452D40, clock)
            self.pe.write_f32(0x452DBC, freeze)
            self.pe.call(0x4094E0)
            self.dll.combat_projectiles(dt, clock, freeze)
            frame = (label, i + 1)
            self.compare(pool, slot, frame)
            for child in range(fragments):
                self.compare(PARTICLE, child, frame)
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
            for scenario in ("flight", "impact", "kill", "edge", "fire", "frozen"):
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
                if scenario in ("impact", "kill", "fire", "frozen"):
                    self.write(CREATURE, 0, creature(510, 500, 1000 if scenario == "impact" else 9))
                    self.write(CREATURE, 1, creature(525, 500, 75))
                self.projectile_frames(
                    (kind, scenario),
                    BULLET,
                    slot,
                    4,
                    0.02 if scenario == "flight" else 0.035,
                    float(scenario == "frozen"),
                )
        self.reset(987)
        self.write(BULLET, 63, struct.pack(BULLET[2], 1, 0.6, 512, 512, 512, 512, 1, 1, 3, 0.4, 0.04, 1, 1))
        self.projectile_frames("delayed burst", BULLET, 63, 5, 0.017, fragments=40)
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
            if pickup == 3:
                assert self.dll.combat_drop_weapon() == pe.read_i32(0x452E68)
            assert self.pe.call(0x422414).eax == self.dll.crt_rand(), ("reward", seed, "next rand")

    def bombs(self):
        pe = self.pe
        self.reset(42)
        pe.write_u8(0x452DB4, 1)
        for va in (0x4387B8, 0x4387BC):
            pe.write_f32(va, 500)
        pe.write_f32(0x452DC8, 0)
        self.write(CREATURE, 0, creature(530, 500, 120))
        self.write(CREATURE, 1, creature(700, 500, 990))
        for frame in range(10):
            pe.write_f32(0x452E94, 0.04)
            pe.run(0x41C094, 0x41C0CB)
            age = pe.read_f32(0x452DC8)
            if age > 1:
                pe.write_f32(0x452DC8, -1)
            elif age >= 0:
                pe.run(0x4121E6, 0x412291, regs={"ebp": 0})
            assert math.isclose(self.dll.combat_bomb(0.04, int(frame == 0)), pe.read_f32(0x452DC8), abs_tol=1e-6)
            for slot in range(2):
                self.compare(CREATURE, slot, ("bomb", frame))
            assert self.dll.combat_experience() == pe.read_i32(0x4384F8)
            self.frames += 1

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
        for weapon, whole_frame in [(w, False) for w in range(1, 21)] + [(2, True), (3, True), (12, True)]:
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
            if whole_frame:
                pe.write_u32(0x438500, 1)
                pe.write_f32(0x438628, 100)
                pe.write_f32(0x4387C0, -100)
                pe.write_u32(0x452E18, 6)
                pe.write_u32(0x452E10, 12)
                self.write(CREATURE, 0, creature(555, 510, 20))
                self.write(BULLET, 2, struct.pack(BULLET[2], 1, 1.57079637, 512, 510, 512, 510, 1, 2, 1, 0.4, 1, 1, 1))
            for i, (keys, x, y) in enumerate(
                [(1, 712, 512), (2, 514, 774), (6, 391, 514), (16, 620, 477), (0, 712, 514), (9, 600, 520)],
            ):
                self.keys = keys
                dt = 0.017
                pe.write_f32(0x438800, x)
                pe.write_f32(0x438804, y)
                pe.write_f32(0x452E94, dt)
                if whole_frame:
                    self.dll.combat_player(dt, keys, x, y, 1)
                    pe.run(0x4183CD, 0x418587, regs={"ebp": 0, "edi": 1, "ebx": 3})
                    self.compare(CREATURE, 0, ("frame", weapon, i))
                    assert self.dll.combat_experience() == pe.read_i32(0x4384F8)
                else:
                    pe.call(0x4126E0)
                    self.dll.combat_player(dt, keys, x, y, 0)
                state = ctypes.c_uint32.from_address(self.symbol("freeware_rng_state")).value
                assert state == pe.rand_state, (weapon, whole_frame, i, state, pe.rand_state)
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

    def draws(self):
        self.reset(1)
        pe = self.pe
        table = pe.read_u32(pe.read_u32(0x452D94))
        calls = []
        state = {}

        def method(slot, n):
            def invoke(call):
                values = tuple(call.arg_f32(i) for i in range(n))
                if slot == 0x90:
                    name = pe.read(call.arg_u32(0), 12).split(b"\x00", 1)[0]
                    return {b"grass1.tga": 6, b"mud1.tga": 7, b"rocket": 5, b"glow": 4}.get(name, 0)
                if slot == 0x94:
                    state["texture"] = call.arg_u32(0)
                elif slot == 0xB8:
                    for i in range(4):
                        state[i] = values
                elif slot == 0xBC:
                    state[call.arg_u32(0)] = values[1:]
                elif slot == 0xAC:
                    state["angle"] = values[0]
                elif slot in (0xC0, 0xC4):
                    calls.append((state["texture"], values, state[2], state.get("angle", 0)))
                return 0

            va = pe.load_code(b"\xc3")
            pe.stub(va, invoke, pop=n * 4)
            pe.write_u32(table + slot, va)

        for slot, n in [
            (0x1C, 5),
            (0x90, 1),
            (0x94, 2),
            (0x98, 0),
            (0xA0, 0),
            (0xAC, 1),
            (0xB0, 4),
            (0xB8, 4),
            (0xBC, 5),
            (0xC0, 4),
            (0xC4, 8),
        ]:
            method(slot, n)
        for va, v in [(0x43BB74, 1), (0x452C14, 2), (0x442490, 3)]:
            pe.write_u32(va, v)
        pe.write_f32(0x43CBC0, 5)
        pe.write_f32(0x43CBC4, -8)
        pe.write_f32(0x452DC4, 1.125)
        self.write(BULLET, 0, bytes(64 * 52))
        samples = 0
        for t in (1, 2, 4, 7, 9, 10, 17, 18):
            for life in (0.4, 0.24):
                for fire in (0, 2):
                    for effects in (0, 1):
                        self.write(
                            BULLET,
                            2,
                            struct.pack(BULLET[2], 1, 0.8, 200, 180, 160, 155, 1.5, 2, t, life, 1, 1, 1),
                        )
                        pe.write_f32(0x452DB8, fire)
                        pe.write_u8(0x44289E, effects)
                        ctypes.c_float.from_address(self.symbol("bonus_fire_bullets_timer")).value = fire
                        calls.clear()
                        pe.call(0x40B570)
                        count = self.dll.combat_draw(1.125, effects)
                        case = (t, life, fire, effects)
                        assert len(calls) == count, (case, len(calls), count)
                        for i, (texture, points, color, angle) in enumerate(calls):
                            record = ctypes.string_at(self.symbol("combat_draw_capture") + i * 64, 64)
                            tex, *floats = struct.unpack("<i14f4x", record)
                            corners = floats[:8]
                            size, rotate = floats[8:10]
                            ours = corners if not size else [*corners[:2], size, size]
                            assert tex == texture and all(
                                math.isclose(a, b, abs_tol=0.001) for a, b in zip(ours, points, strict=True)
                            ), (case, i, tex, texture, ours, points)
                            assert all(
                                math.isclose(a, b, abs_tol=1e-6) for a, b in zip(floats[10:], color, strict=True)
                            ), (case, i, color, floats[10:])
                            if size:
                                assert abs(rotate - angle) < 1e-6, (case, i, rotate, angle)
                        samples += 1
        method(0x28, 4)
        method(0x2C, 1)
        pe.stub(0x404D70, 0, pop=8)  # Empty level-object list in both shipped modes.
        for seed in (1, 87, 13456):
            calls.clear()
            pe.rand_state = seed
            pe.call(0x40E060, 1)
            count = self.dll.combat_terrain(seed)
            assert len(calls) == count == 1470
            base = self.symbol("combat_terrain_capture")
            for i, (texture, points, color, angle) in enumerate(calls):
                x, y, rotation, grass = struct.unpack("<fff?3x", ctypes.string_at(base + 16 * i, 16))
                assert texture == (6 if grass else 7) and points == (x, y, 128, 128)
                assert abs(rotation - angle) < 1e-6
                assert all(abs(a - b) < 1e-6 for a, b in zip(color, (0.7, 0.7, 0.7, 0.9), strict=True))
            assert self.dll.crt_rand() == pe.call(0x422414).eax
        return samples


def check_client(dll, exe, address, target):
    comparison = Comparison(dll, exe, address)
    comparison.bombs()
    comparison.grants()
    comparison.players()
    comparison.creatures()
    comparison.rewards()
    comparison.projectiles()
    check_controls(comparison)
    dispatch_frames = check_frames(comparison, exe)
    visual_cases = comparison.draws()
    print(
        f"1.4.0 {target} combat oracle passed {comparison.frames} frames, 24 reward rolls, 64 perk grants, {dispatch_frames} full frame callbacks and {visual_cases} draw traces.",
        flush=True,
    )


def check_web(stage, exe, sources):
    # Emscripten builds the same translation units as the browser. WASI supplies stdio to the test host.
    import wasmtime

    compiler = shutil.which("em++")
    if not compiler:
        raise SystemExit("em++ is required for --web")
    functions = (
        "combat_bomb",
        "combat_draw",
        "combat_terrain",
        "combat_reset",
        "combat_projectiles",
        "combat_creatures",
        "combat_actors",
        "combat_reward",
        "combat_player",
        "combat_arm",
        "combat_controls",
        "combat_frame_start",
        "combat_frame_step",
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
        "freeware_player_moved",
        "freeware_first_kill_xp",
        "time_scale_factor",
        "freeware_aim_screen",
        "freeware_rainbow_armed",
        "freeware_rainbow_enabled",
        "freeware_secret_weapon_unlocked",
        "combat_frame_fields",
        "combat_frame_flags",
        "combat_draw_capture",
        "combat_terrain_capture",
        "freeware_rng_state",
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
    module = wasmtime.Module.from_file(engine, str(out))

    # Linking the real frame dispatcher also links atomic score-file saves.
    # The oracle uses in-memory boards. Any attempted filesystem mutation is a test failure.
    def unexpected_rename(*_args):
        raise AssertionError("the combat oracle tried to persist a score")

    for entry in module.imports:
        if entry.module == "env" and entry.name == "__syscall_renameat":
            linker.define_func("env", entry.name, entry.type, unexpected_rename)
    exports = linker.instantiate(store, module).exports(store)
    exports["_initialize"](store)
    memory = exports["memory"]

    def pointer(offset):
        return ctypes.addressof(memory.data_ptr(store).contents) + offset

    def function(name):
        fn = exports[name]
        if name == "combat_message":
            return lambda: ctypes.string_at(pointer(fn(store)))
        converters = [float if str(param) in {"f32", "f64"} else int for param in fn.type(store).params]
        return lambda *args: fn(store, *(cast(arg) for cast, arg in zip(converters, args, strict=True)))

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
        dll.combat_player.argtypes = [ctypes.c_float, ctypes.c_int, ctypes.c_float, ctypes.c_float, ctypes.c_int]
        dll.combat_frame_step.argtypes = [ctypes.c_float, ctypes.c_int]
        dll.combat_controls.argtypes = [ctypes.c_int] * 6 + [ctypes.c_float]
        dll.combat_message.restype = ctypes.c_char_p
        dll.combat_health.restype = ctypes.c_float
        dll.combat_bomb.restype = ctypes.c_float
        dll.combat_bomb.argtypes = [ctypes.c_float, ctypes.c_int]
        dll.combat_draw.argtypes = [ctypes.c_float, ctypes.c_int]
        check_client(dll, exe, lambda name: ctypes.addressof(ctypes.c_char.in_dll(dll, name)), "native")
        if args.web:
            check_web(stage, exe, sources)


if __name__ == "__main__":
    main()
