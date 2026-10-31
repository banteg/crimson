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
            elif c.arg_u32(0) == 0x13:
                self.source = c.arg_u32(1)
            elif c.arg_u32(0) == 0x14:
                self.blend = c.arg_u32(1)
            elif c.arg_u32(0) == 0x15:
                self.filter = c.arg_u32(1)

        def quad(c):
            self.calls.append(
                (
                    self.texture,
                    0,
                    self.filter,
                    self.blend,
                    self.source,
                    tuple(c.arg_f32(i) for i in range(4)) + (self.angle, *self.uv, 0, *self.color),
                ),
            )

        def label(c):
            self.calls.append(
                (
                    self.string(c.arg_u32(2)),
                    1,
                    0,
                    0,
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
            0x94: (2, lambda c: setattr(self, "texture", self.textures.get(c.arg_u32(0), f"handle {c.arg_u32(0)}"))),
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
        data = bytearray()
        while len(data) < 384:
            c = self.pe.read_u8(addr + len(data))
            if not c:
                return data.decode("latin1")
            data.append(c)
        raise AssertionError("unterminated UI text")

    def reset_draw(self):
        self.calls.clear()
        self.scale = self.angle = 0
        self.filter = 2
        self.blend = 6
        self.source = 5
        self.uv = (0, 0, 1, 1)
        self.color = (1, 1, 1, 1)
        self.texture = "bullet"

    def compare(self, check, n, case):
        assert n == len(self.calls), (case, "draw count", n, len(self.calls))
        fmt = "<384siiii14f"
        size = struct.calcsize(fmt)
        for i, (value, kind, filt, blend, source, floats) in enumerate(self.calls):
            got = struct.unpack(fmt, ctypes.string_at(check.symbol("combat_ui_draws") + size * i, size))
            actual = got[0].split(b"\0", 1)[0].decode("latin1")
            assert (actual, *got[1:5]) == (value, kind, filt, blend, source), (
                case,
                i,
                (actual, *got[1:5]),
                (value, kind, filt, blend, source),
            )
            assert all(math.isclose(a, b, abs_tol=0.002) for a, b in zip(got[5:], floats, strict=True)), (
                case,
                i,
                value,
                got[5:],
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
    return calls + check_pages(oracle, check) + check_perk_draws(oracle, check)


def check_pages(oracle, check):
    pe = oracle.pe
    pe.stub(0x4073C0, 0)  # Records are supplied at the score-file boundary.
    message = b"A message\non two lines.\0"
    pe.write_u32(0x452D48, pe.alloc(len(message), data=message))
    oracle.dt = 0.125
    calls = 0
    for kind, va in enumerate((0x416560, 0x41E330, 0x41F480, 0x41EFA0)):
        for board in range(4) if kind == 2 else [0]:
            for ticks, flags in [
                (0, 1),
                (4, 0),
                (5, 4),
                (20, 2),
                (32, 8),
                (32, 16),
                (140, 128 | 256),
                (583, 512),
                (930, 0),
                (1600, 64 | 32),
                (128, 1024),
            ]:
                oracle.reset_draw()
                oracle.keys.clear()
                oracle.edges.clear()
                oracle.clicks.clear()
                for bit, key in [(16, 0x39), (32, 1)]:
                    if flags & bit:
                        oracle.edges.add(key)
                for bit, key in [(256, 0xD0), (512, 0xC8)]:
                    if flags & bit:
                        oracle.keys.add(key)
                if flags & 8:
                    oracle.clicks.add(0)
                pe.write_u32(0x42FBAC, 1 if kind in (1, 2) else 7)
                pe.write_u32(0x4428A0, 1 + (board & 1))
                pe.write_u32(0x4428A8, 2 if board & 2 else 1)
                pe.write_u8(0x42FBB4, bool(flags & 1))
                pe.write_u8(0x452D4F, bool(flags & 4))
                pe.write_u8(0x452D4E, bool(flags & 1024))
                pe.write_u8(0x452EEC, 0)
                pe.write_u8(0x452ED5, 0)
                for addr, value in (
                    (0x452D40, 4 + ticks / 16),
                    (0x452D54, 4),
                    (0x42FB9C, 0.5 if flags & 2 else 0.04 if flags & 64 else 1),
                    (0x452EF0, 3),
                    (0x438330, 8 if flags & 128 else 0),
                    (0x438800, 312),
                    (0x438804, 148),
                ):
                    pe.write_f32(addr, value)
                for i in range(100):
                    who = ("Gunner" if i == 1 else "Other") if i < 4 else "10tons"
                    seconds = 160 - i * 7 if i < 4 else 0
                    xp = 2700 - i * 13 if i < 4 else 0
                    if flags & 1024:
                        names = ("Corrupted high score file.", "  (delete *.top files)", "(or press D to do it now)")
                        who = names[i] if i < 3 else " "
                        seconds = xp = 0
                    row = struct.pack("<32sii4f", who.encode(), seconds, seconds if board & 2 else xp, 0, 0, 0, 0)
                    pe.write(0x436CF8 + 56 * i, row)
                pe.write(0x439228, struct.pack("<32sii", b"Gunner", 153, 2687))
                pe.call(va)
                n = check.dll.combat_ui_page(kind, ticks, flags, board)
                case = (hex(va), ticks, flags, board)
                calls += oracle.compare(check, n, case)
                state = (pe.read_f32(0x452E94), pe.read_f32(0x452D54), pe.read_f32(0x42FB9C), pe.read_i32(0x42FBAC))
                got = (ctypes.c_float * 4).from_address(check.symbol("combat_ui_result"))
                assert all(math.isclose(a, b, abs_tol=1e-6) for a, b in zip(got, state, strict=True)), (
                    case,
                    tuple(got),
                    state,
                )
    return calls


def check_perk_draws(oracle, check):
    pe = oracle.pe
    pe.stub(0x421DD6, lambda c: pe.alloc(c.arg_u32(0)))
    pe.stub(0x421B81, 0)

    def duplicate(c):
        data = oracle.string(c.arg_u32(0)).encode("latin1") + b"\0"
        return pe.alloc(len(data), data=data)

    pe.stub(0x42C2EC, duplicate)
    # Run registration, including its original 25-column text wrapping.
    for i in range(48):
        pe.write_u8(0x441FC0 + 20 * i + 16, 1)
    pe.call(0x407920)
    snap = pe.snapshot()
    calls = 0
    for perk in range(1, 33):
        for flags in (0, 3, 4 | 32, 8, 16, 64):
            pe.restore(snap)
            oracle.reset_draw()
            oracle.down.clear()
            oracle.clicks.clear()
            oracle.edges.clear()
            oracle.keys.clear()
            if flags & 8:
                oracle.down.add(0)
            if flags & 16:
                oracle.clicks.add(0)
            pe.write_u32(0x452DA8, 0xFFFFFFFF if flags & 32 else perk)
            pe.write_u32(0x452E70, 2)
            pe.write_u32(0x452D8C, 0)
            pe.write_u32(0x42FBAC, 4)
            pe.write_u32(0x4428A0, 2 if flags & 2 else 1)
            pe.write_u32(0x4428A8, 1)
            pe.write_u8(0x42FBB4, 0)
            pe.write_u8(0x452D4F, 0)
            pe.write_u32(0x452D48, 0)
            pe.write(0x43850C, b"\0" * (48 * 4))
            pe.write_u32(0x43850C + 25 * 4, flags & 1)
            pe.write_u32(0x43850C + perk * 4, pe.read_u32(0x43850C + perk * 4) + int(bool(flags & 4)))
            pe.write(0x43C598, b"\0" * 48)
            pe.write_u8(0x43C598 + perk, 1)
            pe.write_u8(0x43C598 + (2 if perk == 1 else 1), 1)
            for addr, value in [
                (0x452D40, 4.625),
                (0x452D54, 4),
                (0x42FB9C, 1),
                (0x438800, 430 if flags & 8 else 295 if flags & 64 else 100),
                (0x438804, 15 if flags & 8 else 90 + int(perk != 1) * 20),
            ]:
                pe.write_f32(addr, value)
            pe.rand_state = 815
            pe.call(0x415690)
            n = check.dll.combat_ui_perk(perk, flags)
            case = ("perk", perk, flags)
            calls += oracle.compare(check, n, case)
            state = tuple(pe.read_i32(a) for a in (0x452DA8, 0x42FBAC, 0x452E70, 0x43850C + perk * 4))
            observed = tuple((ctypes.c_float * 4).from_address(check.symbol("combat_ui_result")))
            assert state == observed, (case, state, observed)
    return calls
