"""Run the entry-to-return 0x418190 callback with the original HUD, renderer and simulation."""

import ctypes
import math
import struct
import tempfile
from pathlib import Path

from crimson_re.dbg.native_oracle import NativeOracle, SymbolTable


def check_frames(check, exe, bullet_pool, creature_record, *, files=False):
    pe = NativeOracle(exe, symbols=SymbolTable({}), rand_state_address=0x432C40)
    vt = pe.alloc(256)
    obj = pe.alloc(4, data=struct.pack("<I", vt))
    for va in (0x452D94, 0x436110):
        pe.write_u32(va, obj)
    pe.write_u32(0x43CBB8, pe.alloc(0x80))
    pe.write_u32(0x452EA0, pe.alloc(0x30))
    keys, edges, clicks = set(), set(), set()
    dt = 0.03125
    textures = {"bullet_i": 400, "bullet": 401}
    pe.write_u32(0x43BB74, 401)
    pe.write_u32(0x442490, 400)
    draw = {"texture": 0, "angle": 0, "color": (1, 1, 1, 1)}
    quads, labels, blends, label_positions = [], [], [], []
    terrain_filters = []

    world_labels = []

    def text(call):
        site = call.return_address
        if 0x411900 < site < 0x411BC8:
            world_labels.append(pe.read(call.arg_u32(2), 32).split(b"\0", 1)[0])
        if (
            0x416560 < site < 0x4167A6
            or 0x41E330 < site < 0x41EF9D
            or 0x41F480 < site < 0x41FB93
            or 0x416A00 < site < 0x417CB8
            or 0x419990 < site < 0x41B655
            or 0x41D700 < site < 0x41DF00
        ):
            value = pe.read(call.arg_u32(2), 160).split(b"\0", 1)[0].decode("ascii")
            label_positions.append(len(quads))
            labels.append((value, call.arg_f32(0), call.arg_f32(1), draw.get("scale", 1), *draw["color"]))

    def config(call):
        if call.arg_u32(0) == 0x15:
            draw["filter"] = call.arg_u32(1)
        if call.arg_u32(0) == 0x14:
            draw["blend"] = call.arg_u32(1)
        if call.arg_u32(0) == 0x18:
            draw["scale"] = call.arg_f32(1)

    def texture(call):
        value = pe.read(call.arg_u32(0), 64).split(b"\0", 1)[0].decode("latin1")
        return textures.setdefault(value, len(textures) + 1)

    def quad(call):
        if 0x40F340 <= call.return_address < 0x40F5D1:
            terrain_filters.append(draw.get("filter", 2))
        # Capture the quads issued by the dispatcher, including both of its animated cursors.
        if (
            0x419182 < call.return_address < 0x419462  # Editor radius, brush preview and cursor.
            or 0x415690 < call.return_address < 0x416559
            or 0x416560 < call.return_address < 0x4167A6
            or 0x41EFA0 < call.return_address < 0x41F230
            or 0x41E330 < call.return_address < 0x41EF9D
            or 0x41F480 < call.return_address < 0x41FB93
            or 0x416A00 < call.return_address < 0x417CB8
            or 0x419990 < call.return_address < 0x41A560
            or 0x41B650 < call.return_address < 0x41B910
            or 0x41DE37 < call.return_address < 0x41E0E1
            or 0x41C000 < call.return_address < 0x41C743
            or 0x41D000 < call.return_address < 0x41D790
        ):
            name = next((name for name, handle in textures.items() if handle == draw["texture"]), None)
            if draw["texture"] == 999:
                name = "arrow"
            blends.append(draw.get("blend", 6))
            quads.append((name, tuple(call.arg_f32(i) for i in range(4)), draw["angle"], draw["color"]))

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
        0x68: 0,
        0x6C: 0,
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
        0xCC: 0,
    }
    for slot, argc in slots.items():
        addr = pe.load_code(b"\xc3")
        ret = {
            0x1C: config,
            0xC8: text,
            0xCC: lambda c: (
                label_positions.append(len(quads))
                or labels.append(
                    (
                        pe.read(c.arg_u32(4), 64).split(b"\0")[0].decode(),
                        c.arg_f32(1),
                        c.arg_f32(2),
                        draw["scale"],
                        *draw["color"],
                    ),
                )
            ),
            0x90: texture,
            0x94: lambda c: draw.update(texture=c.arg_u32(0)),
            0xAC: lambda c: draw.update(angle=c.arg_f32(0)),
            0xB8: lambda c: draw.update(color=tuple(c.arg_f32(i) for i in range(4))),
            0xC0: quad,
            0x74: lambda _: -1,
            0x60: lambda _: dx,
            0x64: lambda _: dy,
            0x38: lambda _: dt,
            0x3C: lambda _: 1 / dt,
            0x40: lambda c: (c.arg_u32(0) & 255) in keys,
            0x4C: lambda c: c.arg_u32(0) in clicks,
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
        0x402390,
        0x421B81,
        0x421B40,  # The PE host owns atexit registration for the editor cursor.
        0x4073C0,
        0x407780,
    ):
        pe.stub(va, 0)
    name_key = 0xA7
    pe.stub(0x417CC0, lambda _: name_key)
    pe.stub(0x406FF0, 0)  # Score writes are exercised separately against the original .top codec.
    pe.write_u32(0x452D34, pe.alloc(1, data=b"\0"))
    pe.write_u32(0x43BB70, 999)
    # Use the same explicit graphics options on each machine.
    for va in (0x44289E, 0x44289F, 0x44289B, 0x4428D4):
        pe.write_u8(va, 1)
    pe.stub(0x42C2EC, lambda c: c.arg_u32(0))
    # Original register-perks initializer binds indices used by both the dispatcher and its callees.
    pe.stub(0x421DD6, lambda c: pe.alloc(c.arg_u32(0)))
    pe.call(0x407920)
    for i, addr in enumerate((0x431BC8, 0x431BB8, 0x431B94, 0x432580, 0x432574, 0x432564, 0x432554, 0x431B34)):
        pe.write_u32(0x4387C8 + 4 * i, addr)
    for i, address in enumerate((0x432528, 0x432514, 0x43250C)):
        pe.write_u32(0x4387AC + 4 * i, address)
    for i, address in enumerate((0x4325CC, 0x4325B8, 0x4325A0, 0x436128, 0x43258C)):
        pe.write_u32(0x452C00 + 4 * i, address)
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
    # The install disabled Level Test. Supply the same valid 32x24 brush to both
    # machines so the editor callback can be exercised without a shipped map.
    level = pe.read_u32(0x43CBB8)
    brush = pe.alloc(48)
    pe.write_f32(brush + 12, 32)
    pe.write_f32(brush + 16, 24)
    pe.write_u32(brush + 20, 999)
    brushes = pe.alloc(4, data=struct.pack("<I", brush))
    pe.write_u32(0x452D1C, brushes)
    pe.write_u32(0x452D20, brushes + 4)
    pe.stub(0x421DD6, lambda c: pe.alloc(c.arg_u32(0)))
    base = pe.snapshot()
    callbacks = 0
    scenarios = [
        ("survival", 2, 1, 3, 1, [0, 8, 0, 1, 0]),
        ("pickup expiry", 2, 1, 3, 1048576, [0, 0, 0]),
        ("co-op", 2, 2, 3, 1 | 4 | 8, [0, 0, 0]),
        ("career", 1, 1, 3, 1 | 16, [0, 8, 0]),
        ("pause", 1, 1, 3, 16, [1, 0, 0]),
        ("perk", 1, 1, 3, 2 | 16, [2, 1, 0, 4]),
        ("death", 2, 1, 3, 32 | 256, [0, 0, 0]),
        ("both dead", 1, 2, 3, 32 | 64, [0, 0]),
        ("surviving partner", 2, 2, 3, 32, [0, 0]),
        ("revive", 1, 1, 3, 32 | 128, [0, 0]),
        ("menu", 2, 1, 1, 0, [0, 0, 0]),
        ("O filter override", 2, 1, 3, 0, [0, 16384, 16384, 0]),
        ("mouse motion", 2, 1, 3, 0, [4096, 4096 | 8192, 4096, 0]),
        ("name", 2, 1, 9, 0, [0, 256, 128, 256, 4]),
        ("handoff", 1, 2, 6, 512 | 32 | 64, [0, 0, 0]),
        ("rifle burst", 2, 1, 3, 1024, [16, 16, 16, 16, 16]),
        ("first kill", 2, 1, 3, 2048, [0] * 22),
        ("resume", 2, 1, 3, 0, [1, 0, 4, 0]),
        ("level clear", 3, 1, 3, 0, [0, 0]),
        ("level test start", 3, 1, 1, 0, [0, 4, 0]),
        ("editor", 4, 1, 3, 0, [0, 512, 1024, 2048]),
        ("begin and fire", 2, 1, 1, 0, [0, 4, 0, 16]),
        ("return to game", 2, 1, 6, 512 | 32, [0, 0, 256, 4, 1] + [0] * 16 + [4, 0]),
        ("options", 1, 1, 1, 0, [32, 32, 32, 32, 32, 4, 0, 32, 4]),
    ]
    title_cases = {
        "birthday": 4096,
        "memorial": 8192,
        "snow": 16384,
        "solstice": 32768,
        "assembly": 65536,
        "online": 131072,
        "calibration": 262144,
        "rebinding": 524288,
    }
    for title, flag in title_cases.items():
        scenarios.append((title, 1, 1, 1, flag, [0, 4, 64, 32, 4, 0, 4, 0, 4] if title == "calibration" else [0, 0, 0]))
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
        if name == "pickup expiry":
            pe.write_u32(0x452E60, 0)  # The released no-pickup sentinel is zero-initialized.
            pe.write_f32(0x4369F0, 310)
            pe.write_f32(0x4369F4, 297)
            pe.write_f32(0x452E64, 0.015625)
            pe.write_u32(0x4387E8, 2)
        if name == "level test start":
            pe.stub(0x421DC3, 0)  # No level files are present in the released install.
        for va, val in ((0x4428A8, mode), (0x4428A0, count), (0x42FBAC, phase), (0x452E70, int(bool(flags & 2)))):
            pe.write_u32(va, val)
        pe.write_u8(0x452DB4, phase != 1)
        pe.write_f32(0x42FBE4, 0.8)
        pe.write_f32(0x42FBE8, 0.7)
        pe.write_f32(0x42FBEC, 50)
        pe.write_f32(0x452D54, 2.01 if flags & 512 else 5)
        if flags & 2048:
            data = creature_record(522, 512, 1)
            # Existing bullet intersects the first slot before the players move this frame.
            bullet = struct.pack(bullet_pool[2], 1, 1.57079637, 512, 512, 512, 512, 1, 2, 1, 0.4, 1, 1, 1)
            for va, symbol, record in [(0x442AF8, "creature_pool", data), (bullet_pool[1], bullet_pool[0], bullet)]:
                pe.write(va, bytes(record))
                ctypes.memmove(check.symbol(symbol), bytes(record), len(record))
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
                (0x438504, 0 if flags & 1024 else 0.8),
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
        if name in title_cases:
            for mask, addr in (
                (4096, 0x452D68),
                (8192, 0x452D69),
                (16384, 0x452D6B),
                (32768, 0x452D6A),
                (131072, 0x452E75),
                (262144, 0x452D6D),
                (524288, 0x452D6C),
            ):
                pe.write_u8(addr, int(bool(flags & mask)))
            pe.write_u8(0x452E74, int(bool(flags & (262144 | 524288))))
            pe.write_u32(0x4428C0, 100)
            pe.write_u32(0x452D60, 8 if flags & 65536 else 0)
            pe.write_f32(0x452D54, 2)
            pe.write_u8(0x42FBA0, 0)
        pe.rand_state = 42
        for frame, bits in enumerate(inputs):
            dx, dy = (43, -17) if bits & 4096 else (0, 0)
            keys.clear()
            if bits & 16384:
                keys.add(0x18)
            if bits & 8192:
                keys.add(0x1D)
            edges.clear()
            for mask, key in ((1, 1), (2, 0x39), (8, 32), (16, 36)):
                if bits & mask:
                    keys.add(key)
            clicks.clear()
            if bits & 512:
                edges.update((3, 0xCD, 0x2E))
                keys.update((0x2A, 0xC9, 0xD2, 0x1F, 0x30))
            if bits & 1024:
                edges.update((0x39, 0x14))
                keys.add(0x2F)
            if bits & 2048:
                edges.add(0x11)
                clicks.add(1)
            if bits & 32:
                edges.add(0xD0)
            if bits & 64:
                edges.add(0xC8)
            if bits & 1:
                edges.add(1)
            if bits & 4:
                edges.add(0x1C)
                keys.add(0x1C)
            name_key = 9 if bits & 4 else 8 if bits & 128 else ord("x") if bits & 256 else 0xA7
            terrain_filters.clear()
            quads.clear()
            labels.clear()
            world_labels.clear()
            blends.clear()
            label_positions.clear()
            pe.call(0x418190)
            state = check.dll.combat_frame_step(dt, bits)
            label = name, frame
            if name == "O filter override":
                expected_filter = 3 if bits & 16384 else 2
                assert terrain_filters == [expected_filter], label
                got = ctypes.c_float.from_address(check.symbol("combat_frame_fields") + 31 * 4).value
                assert got == expected_filter, (label, got, expected_filter)
            if name == "pickup expiry":
                state_fields = (ctypes.c_float * 31).from_address(check.symbol("combat_frame_fields"))
                assert list(state_fields[28:31]) == [pe.read_f32(0x452E64), pe.read_i32(0x4387E8), len(world_labels)], (
                    label,
                    world_labels,
                    list(state_fields[28:31]),
                )
                assert world_labels == ([b"Freeze"] if frame < 2 else []), (label, world_labels)
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
            if name != "level clear":
                count = check.dll_globals("combat_frame_quad_count").value
                first = 0
                if name == "editor":
                    # Layer and trigger passes precede the editor's own preview draws.
                    expected = ["radius", "arrow", "aim32"] if bits & 512 else ["arrow", "aim32"]
                    assert [q[0] for q in quads] == expected, (label, quads)
                    first = count - len(quads)
                    assert first >= 0, (label, count, quads)
                else:
                    assert count == len(quads), (label, "draw count", quads, count)
                for j, (texture_name, coords, angle, color) in enumerate(quads):
                    buf = ctypes.string_at(check.symbol("combat_frame_quads") + 52 * (first + j), 52)
                    ours, *values = struct.unpack("<16s9f", buf)
                    if name in title_cases or name in ("menu", "options", "editor"):
                        blend = ctypes.c_int.from_address(check.symbol("combat_frame_blends") + (first + j) * 4).value
                        assert blend == blends[j], (label, texture_name, "destination blend", blend, blends[j])
                    ours = ours.split(b"\0", 1)[0].decode()
                    assert texture_name == ours and all(
                        math.isclose(x, y, abs_tol=0.002) for x, y in zip(values, (*coords, angle, *color), strict=True)
                    ), (label, texture_name, ours, (*coords, angle, *color), values)
            if name in title_cases or name in ("menu", "options", "name", "return to game", "begin and fire"):
                size = check.dll_globals("combat_frame_label_count").value
                assert size == len(labels), (label, "label count", labels, size)
                for j, (value, *numbers) in enumerate(labels):
                    buf = ctypes.string_at(check.symbol("combat_frame_labels") + 188 * j, 188)
                    raw, *values = struct.unpack("<160s7f", buf)
                    before = ctypes.c_int.from_address(check.symbol("combat_frame_label_positions") + j * 4).value
                    assert before == label_positions[j], (label, value, "submission order", before, label_positions[j])
                    ours = raw.split(b"\0", 1)[0].decode()
                    assert ours == value and all(
                        math.isclose(x, y, abs_tol=0.0001) for x, y in zip(values, numbers, strict=True)
                    ), (label, "text", value, ours, numbers, values)
            if name in ("begin and fire", "return to game", "options"):
                for i, va in ((24, 0x452ECD), (25, 0x452E74)):
                    got = ctypes.c_float.from_address(check.symbol("combat_frame_fields") + 4 * i).value
                    assert got == pe.read_u8(va), (label, hex(va), got, pe.read_u8(va))
                if state == 9:
                    assert ctypes.c_float.from_address(
                        check.symbol("combat_frame_fields") + 4 * 27,
                    ).value == pe.read_i32(0x452ED8), label
            if name == "first kill":
                assert (
                    pe.read_u32(0x4387F8)
                    == ctypes.c_float.from_address(check.symbol("combat_frame_fields") + 22 * 4).value
                ), label
                if frame == len(inputs) - 1:
                    assert pe.read_u32(0x4387F8) == 1, label
            if name == "editor":
                layer_count = (pe.read_u32(level + 0x2C) - pe.read_u32(level + 0x28)) // 4
                expected = [
                    pe.read_i32(0x452EDC),
                    pe.read_i32(0x452EE0),
                    *(
                        pe.read_f32(v)
                        for v in (0x452EE4, 0x42FBE4, 0x42FBE8, 0x42FBEC, 0x438808, 0x43880C, level, level + 4)
                    ),
                    pe.read_u8(level + 12),
                    layer_count,
                    (pe.read_u32(level + 0x4C) - pe.read_u32(level + 0x48)) // 4,
                ]
                if layer_count:
                    obj = pe.read_u32(pe.read_u32(level + 0x28))
                    expected.extend(
                        [
                            *(pe.read_f32(obj + o) for o in (0, 4, 8, 12, 16)),
                            pe.read_u8(obj + 24),
                            *(pe.read_f32(obj + o) for o in (32, 36, 44)),
                        ],
                    )
                observed = (ctypes.c_float * len(expected)).from_address(check.symbol("combat_level_fields"))
                for j, (x, y) in enumerate(zip(expected, observed, strict=True)):
                    assert math.isclose(x, y, abs_tol=0.001), (label, "editor", j, x, y)
            if name == "editor" and frame == len(inputs) - 1 and files:
                check_level_file(pe, level, check.dll)
            callbacks += 1
    return callbacks


def check_level_file(pe, level, client):
    # Run the original level serializer, replacing only its CRT file descriptor with memory.
    encoded = bytearray()

    def write(call):
        size = call.arg_u32(1) * call.arg_u32(2)
        encoded.extend(pe.read(call.arg_u32(0), size))
        return call.arg_u32(2)

    pe.stub(0x421DC3, pe.alloc(4))
    pe.stub(0x422138, write)
    pe.stub(0x421C22, 0)
    pe.call(0x4040F0, pe.alloc(8, data=b"map.lvl\0"), ecx=level)
    with tempfile.TemporaryDirectory() as tmp:
        output = Path(tmp) / "map.lvl"
        path = bytes(output)
        assert client.combat_level_file(path, False)
        assert output.read_bytes() == encoded
        assert client.combat_level_file(path, True)
        output.write_bytes(encoded[:-1])
        assert not client.combat_level_file(path, True)
        assert client.combat_level_file(path, False)
        assert output.read_bytes() == encoded
