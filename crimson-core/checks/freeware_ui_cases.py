"""Compare ordered pre-raster HUD and menu submissions with the 1.4.0 x86 executable."""

import ctypes
import math
import struct

from crimson_re.dbg.native_oracle import NativeOracle, SymbolTable


class UiOracle:
    def __init__(self, exe):
        pe = self.pe = NativeOracle(exe, symbols=SymbolTable({}), rand_state_address=0x432C40)
        table = pe.alloc(256)
        obj = pe.alloc(4, data=struct.pack("<I", table))
        pe.write_u32(0x452D94, obj)
        self.textures = {400: "bullet_i", 401: "bullet"}
        pe.write_u32(0x442490, 400)
        pe.write_u32(0x43BB74, 401)
        pe.write_u32(0x452E14, 11)
        pe.write_u32(0x42FB90, 1024)
        pe.write_u32(0x42FB94, 768)
        self.dt = 0.03125
        self.keys, self.edges, self.down, self.clicks = set(), set(), set(), set()
        self.calls = []
        self.reset_draw()

        def texture(c):
            name = self.string(c.arg_u32(0))
            if name not in self.textures.values():
                self.textures[500 + len(self.textures)] = name
            return next(k for k, v in self.textures.items() if v == name)

        def config(c):
            if c.arg_u32(0) == 0x18:
                self.scale = c.arg_f32(1)
            elif c.arg_u32(0) == 0x15:
                self.filter = c.arg_u32(1)

        def quad(c):
            self.calls.append(
                (
                    self.texture,
                    0,
                    self.filter,
                    tuple(c.arg_f32(i) for i in range(4)) + (self.angle, *self.uv, 0, *self.color),
                ),
            )

        def label(c):
            self.calls.append(
                (
                    self.string(c.arg_u32(2)),
                    1,
                    0,
                    (c.arg_f32(0), c.arg_f32(1), 0, 0, 0, 0, 0, 1, 1, self.scale, *self.color),
                ),
            )

        for slot, (count, callback) in {
            0x1C: (5, config),
            0x38: (0, lambda _: self.dt),
            0x40: (1, lambda c: (c.arg_u32(0) & 255) in self.keys),
            0x44: (1, lambda c: c.arg_u32(0) in self.edges),
            0x48: (1, lambda c: c.arg_u32(0) in self.down),
            0x4C: (1, lambda c: c.arg_u32(0) in self.clicks),
            0x90: (1, texture),
            0x94: (2, lambda c: setattr(self, "texture", self.textures[c.arg_u32(0)])),
            0x98: (0, 0),
            0xA0: (0, 0),
            0xAC: (1, lambda c: setattr(self, "angle", c.arg_f32(0))),
            0xB0: (4, lambda c: setattr(self, "uv", tuple(c.arg_f32(i) for i in range(4)))),
            0xB8: (4, lambda c: setattr(self, "color", tuple(c.arg_f32(i) for i in range(4)))),
            0xC0: (4, quad),
            0xC8: (3, label),
        }.items():
            fn = pe.load_code(b"\xc3")
            pe.stub(fn, callback, pop=4 * count, returns="st0" if slot == 0x38 else "eax")
            pe.write_u32(table + slot, fn)

    def string(self, addr):
        return self.pe.read(addr, 384).split(b"\0", 1)[0].decode("latin1")

    def reset_draw(self):
        self.calls.clear()
        self.scale = self.angle = 0
        self.filter = 2
        self.uv = (0, 0, 1, 1)
        self.color = (1, 1, 1, 1)
        self.texture = "bullet"

    def compare(self, check, n, case):
        assert n == len(self.calls), (case, "draw count", n, len(self.calls))
        fmt = "<384sii14f"
        size = struct.calcsize(fmt)
        for i, (value, kind, filt, floats) in enumerate(self.calls):
            got = struct.unpack(fmt, ctypes.string_at(check.symbol("combat_ui_draws") + size * i, size))
            actual = got[0].split(b"\0", 1)[0].decode("latin1")
            assert (actual, *got[1:3]) == (value, kind, filt), (case, i, (actual, *got[1:3]), (value, kind, filt))
            assert all(math.isclose(a, b, abs_tol=0.002) for a, b in zip(got[3:], floats, strict=True)), (
                case,
                i,
                value,
                got[3:],
                floats,
            )
        return n


def check_ui(check, exe):
    oracle = UiOracle(exe)
    pe = oracle.pe
    calls = 0
    for mode in (1, 2, 3):
        for count in (1, 2):
            for variant in range(8):
                oracle.reset_draw()
                pe.write_u32(0x42FBAC, 6 if variant & 2 else 3)
                pe.write_u32(0x4428A0, count)
                pe.write_u32(0x4428A8, mode)
                pe.write_u8(0x452DB4, not variant & 4)
                pe.write_u32(0x452E70, variant & 1)
                pe.write_u32(0x43850C + 4 * 11, variant & 1)
                pe.write_f32(0x452DC4, 13.875)
                pe.write_f32(0x452E94, 0.03125)
                pe.write_f32(0x452D74, 0.25 if variant & 2 else 0.0)
                for i in range(2):
                    off = 392 * i
                    hp = (0 if variant & 2 else 37) if i else (0 if variant & 4 else 180 if variant & 1 else 75)
                    for addr, f in (
                        (0x4384A0, hp),
                        (0x4384E4, 2.5 if i else 7.75),
                        (0x4385DC, 12 if i else 45),
                        (0x4384E8, -0.5 if i else 2.2 if variant & 2 else 0.625),
                        (0x438508, 1.25),
                    ):
                        pe.write_f32(addr + off, f)
                    for addr, k in ((0x4384FC, 30), (0x4384F8, 12 if variant & 4 else 146), (0x4385D4, i + 1)):
                        pe.write_u32(addr + off, k)
                pe.call(0x416A00)
                n = check.dll.combat_ui_hud(mode, count, variant)
                case = ("HUD", mode, count, variant)
                calls += oracle.compare(check, n, case)
                state = (pe.read_f32(0x452DC4), pe.read_f32(0x452D74), pe.read_i32(0x4384FC), pe.read_i32(0x452D8C))
                got = (ctypes.c_float * 4).from_address(check.symbol("combat_ui_result"))
                assert tuple(got) == state, (case, tuple(got), state)
    return calls
