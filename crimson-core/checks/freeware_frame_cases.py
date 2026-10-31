"""Run the entry-to-return 0x418190 callback with the original HUD, renderer and simulation."""

import ctypes
import math
import struct

from crimson_re.dbg.native_oracle import NativeOracle, SymbolTable


def check_frames(check, exe):
    pe = NativeOracle(exe, symbols=SymbolTable({}), rand_state_address=0x432C40)
    vt = pe.alloc(256)
    obj = pe.alloc(4, data=struct.pack("<I", vt))
    for va in (0x452D94, 0x436110):
        pe.write_u32(va, obj)
    pe.write_u32(0x43CBB8, pe.alloc(0x80))
    pe.write_u32(0x452EA0, pe.alloc(0x30))
    keys, edges = set(), set()
    dt = 0.03125
    slots = {
        8: 1,
        0x1C: 5,
        0x28: 4,
        0x2C: 1,
        0x38: 0,
        0x3C: 0,
        0x40: 1,
        0x44: 1,
        0x48: 1,
        0x4C: 1,
        0x54: 2,
        0x58: 0,
        0x5C: 0,
        0x60: 0,
        0x64: 0,
        0x74: 1,
        0x78: 1,
        0x90: 1,
        0x94: 2,
        0x98: 0,
        0x9C: 0,
        0xA0: 0,
        0xAC: 1,
        0xB0: 4,
        0xB4: 3,
        0xB8: 4,
        0xBC: 5,
        0xC0: 4,
        0xC4: 8,
        0xC8: 3,
    }
    for slot, argc in slots.items():
        addr = pe.load_code(b"\xc3")
        ret = {
            0x38: lambda _: dt,
            0x3C: lambda _: 1 / dt,
            0x40: lambda c: (c.arg_u32(0) & 255) in keys,
            0x44: lambda c: (c.arg_u32(0) & 255) in edges,
        }.get(slot, 0)
        pe.stub(addr, ret, pop=4 * argc, returns="st0" if slot in (0x38, 0x3C, 0x60, 0x64) else "eax")
        pe.write_u32(vt + slot, addr)
    # Host I/O only: audio playback, console text, score files, keyboard character and CRT string allocation.
    for va in (
        0x405630,
        0x4056D0,
        0x405760,
        0x405890,
        0x405C80,
        0x402390,
        0x421B81,
        0x422242,
        0x4073C0,
        0x407780,
        0x41EFA0,
    ):
        pe.stub(va, 0)
    pe.stub(0x417CC0, 0xA7)
    pe.stub(0x42C2EC, lambda c: c.arg_u32(0))
    # Original register-perks initializer binds indices used by both the dispatcher and its callees.
    pe.stub(0x4078B0, lambda c: c.arg_u32(0))
    pe.call(0x407920)
    for i, addr in enumerate((0x431BC8, 0x431BB8, 0x431B94, 0x432580, 0x432574, 0x432564, 0x432554, 0x431B34)):
        pe.write_u32(0x4387C8 + 4 * i, addr)
    for va, val in (
        (0x42FB90, 1024),
        (0x42FB94, 768),
        (0x42FBD8, 1024),
        (0x42FBDC, 1024),
        (0x452E60, 99),
        (0x4387E8, 99),
        (0x4428AC, 2),
        (0x4428B0, 2),
        (0x4428B8, 2),
    ):
        pe.write_u32(va, val)
    for va, val in (
        (0x42FB8C, 1),
        (0x452D40, 5),
        (0x452D54, 5),
        (0x452DC4, 7),
        (0x438800, 310),
        (0x438804, 169),
        (0x43CBC4, -128),
        (0x452DC8, -1),
        (0x4387C0, -100),
    ):
        pe.write_f32(va, val)
    pe.write_u8(0x452D50, 1)
    pe.write_u8(0x42FBE0, 1)
    pe.write_u8(0x452DA4, 1)
    base = pe.snapshot()
    callbacks = 0
    scenarios = [
        ("survival", 2, 1, 3, 1, [0, 8, 0, 1, 0]),
        ("co-op", 2, 2, 3, 1 | 4 | 8, [0, 0, 0]),
        ("career", 1, 1, 3, 1 | 16, [0, 8, 0]),
        ("pause", 1, 1, 3, 16, [1, 0, 0]),
        ("perk", 1, 1, 3, 2 | 16, [2]),
        ("death", 2, 1, 3, 32 | 256, [0, 0, 0]),
        ("both dead", 1, 2, 3, 32 | 64, [0, 0]),
        ("surviving partner", 2, 2, 3, 32, [0, 0]),
        ("revive", 1, 1, 3, 32 | 128, [0, 0]),
        ("menu", 2, 1, 1, 0, [0, 0, 0]),
        ("name", 2, 1, 9, 0, [0, 0]),
    ]
    fields = (
        0x452D40,
        0x452E94,
        0x452DC4,
        0x42FB8C,
        0x43CBC0,
        0x43CBC4,
        0x452D78,
        0x452BF8,
        0x452BFC,
        0x452D9C,
        0x452E7C,
        0x452DB0,
        0x452DBC,
        0x452E6C,
        0x452DC8,
        0x4384A0,
        0x438628,
        0x4384F8,
        0x452E70,
        0x452DB4,
        0x452D5C,
        0x452D54,
    )
    for name, mode, count, phase, flags, inputs in scenarios:
        pe.restore(base)
        check.dll.combat_frame_start(mode, count, phase, flags)
        for va, val in ((0x4428A8, mode), (0x4428A0, count), (0x42FBAC, phase), (0x452E70, int(bool(flags & 2)))):
            pe.write_u32(va, val)
        pe.write_u8(0x452DB4, phase != 1)
        pe.write_f32(0x452E7C, 0 if flags & 1 else 2)
        pe.write_f32(0x452DBC, 0.05 if flags & 4 else 0)
        pe.write_f32(0x452E6C, 0.05 if flags & 8 else 0)
        for i in range(2):
            offset = i * 392
            for va, val in (
                (0x438490, 512 + 80 * i),
                (0x438494, 512),
                (0x4384AC, 48),
                (0x4384D0, 2),
                (0x4384A0, 0 if flags & (32 << i) else 100),
                (0x4385CC, 1),
                (0x4385DC, 30 if mode == 2 else 10),
                (0x4384E4, 30 if mode == 2 else 10),
                (0x438504, 0.8),
            ):
                pe.write_f32(va + offset, val)
            for va, val in (
                (0x4385D4, 2 if mode == 2 else 1),
                (0x438500, 1),
                (0x4384F8, 66 if flags & 128 and i == 0 else 0),
                (0x43850C + 6 * 4, 2 if flags & 16 else 0),
                (0x43850C + 23 * 4, int(bool(flags & 256))),
            ):
                pe.write_u32(va + offset, val)
            pe.write(0x4385F4 + offset, bytes(range(32 + i * 5, 37 + i * 5)))
        pe.rand_state = 42
        for frame, bits in enumerate(inputs):
            keys.clear()
            edges.clear()
            for mask, key in ((1, 1), (2, 0x39), (8, 32), (16, 36)):
                if bits & mask:
                    keys.add(key)
            if bits & 4:
                edges.add(0x1C)
            pe.call(0x418190)
            state = check.dll.combat_frame_step(dt, bits)
            label = name, frame
            assert state == pe.read_i32(0x42FBAC), (label, "state", state, pe.read_i32(0x42FBAC))
            for off, va in enumerate(fields):
                expected = pe.read_i32(va) if off in (17, 18) else pe.read_u8(va) if off == 19 else pe.read_f32(va)
                got = ctypes.c_float.from_address(check.symbol("combat_frame_fields") + off * 4).value
                assert math.isclose(got, expected, abs_tol=0.001), (label, hex(va), expected, got)
            assert pe.read(0x4428F0, 8) == ctypes.string_at(check.symbol("combat_frame_flags"), 8), (
                label,
                "random flags",
            )
            got = ctypes.c_uint.from_address(check.symbol("freeware_rng_state")).value
            assert pe.rand_state == got, (label, "rng", pe.rand_state, got)
            callbacks += 1
    return callbacks
