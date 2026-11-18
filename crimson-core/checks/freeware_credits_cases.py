"""Compare early credits draw order, scroll positions and dismissal with each original PE."""

import math
import struct

from crimson_re.dbg.native_oracle import NativeOracle, SymbolTable


def check_credits(exe, edition, lines):
    early = edition == "1.0.2"
    pe = NativeOracle(exe, symbols=SymbolTable({}))
    interface, routine, dt, clock, since, alpha, pending, opened, state, bullet = (
        (0x4287EC, 0x40EDA0, 0x428884, 0x428888, 0x4287E0, 0x41C084, 0x41C0A8, 0x42888C, 0x41C09C, 0x424564)
        if early
        else (0x447754, 0x4183F0, 0x447828, 0x447720, 0x44772C, 0x4290C4, 0x4290DC, 0x447830, 0x4290D4, 0x432EE4)
    )
    if not early:
        pe.write_u32(0x4290B8, 640)
        pe.write_u32(0x4290BC, 480)
    pe.write_u32(bullet, 71)
    vt = pe.alloc(256)
    pe.write_u32(interface, pe.alloc(4, data=struct.pack("<I", vt)))
    draw = {}
    calls = []
    held, edges, clicks = set(), set(), set()

    def install(slot, argc, fn, *, returns="eax"):
        address = pe.load_code(b"\xc3")
        pe.stub(address, fn, pop=4 * argc, returns=returns)
        pe.write_u32(vt + slot, address)

    def config(c):
        opt = c.arg_u32(0)
        if opt == (0x11 if early else 0x18):
            draw["scale"] = c.arg_f32(2)
        elif opt == (0xF if early else 0x15):
            draw["filter"] = c.arg_u32(1)
        elif opt == (0xD if early else 0x13):
            draw["source"] = c.arg_u32(1)
        elif opt == (0xE if early else 0x14):
            draw["blend"] = c.arg_u32(1)

    def quad(c):
        assert draw["texture"] == 71
        calls.append(
            (
                "creditbg",
                "bullet",
                *(c.arg_f32(i) for i in range(4)),
                draw["angle"],
                *draw["uv"],
                *draw["color"],
                draw["filter"],
                draw["source"],
                draw["blend"],
            ),
        )

    def text(c):
        raw = pe.read(c.arg_u32(2), 128).split(b"\0", 1)[0]
        calls.append(("credittext", c.arg_f32(0), c.arg_f32(1), draw["scale"], *draw["color"], raw.hex()))

    install(0x14 if early else 0x1C, 7, config)
    install(0x30 if early else 0x38, 0, lambda _: 0.125, returns="st0")
    install(0x38 if early else 0x40, 1, lambda c: (c.arg_u32(0) & 255) in held)
    install(0x3C if early else 0x44, 1, lambda c: c.arg_u32(0) in edges)
    install(0x44 if early else 0x4C, 1, lambda c: c.arg_u32(0) in clicks)
    install(0x70 if early else 0x8C, 1, lambda c: draw.update(texture=c.arg_u32(0)))
    install(0x74 if early else 0x90, 0, 0)
    install(0x7C if early else 0x98, 0, 0)
    install(0x80 if early else 0x9C, 1, lambda c: draw.update(angle=c.arg_f32(0)))
    install(0x84 if early else 0xA0, 4, lambda c: draw.update(uv=tuple(c.arg_f32(i) for i in range(4))))
    install(0x8C if early else 0xA8, 4, lambda c: draw.update(color=tuple(c.arg_f32(i) for i in range(4))))
    install(0x94 if early else 0xB0, 4, quad)
    install(0x9C if early else 0xB8, 3, text)
    rows = iter(row.split() for row in lines if row.startswith(("credits ", "credittext ", "creditbg ")))
    frames = draws = 0
    for tag, *args in rows:
        assert tag == "credits", tag
        age, opacity, reset, space, esc, enter, click, tick, *result = map(float, args)
        if tick == 0:
            pe.write_f32(alpha, opacity)
            pe.write_u8(pending, int(reset))
            pe.write_u32(state, 1)
            pe.write_u8(opened, 1)
            pe.write_f32(since, 4)
            draw.update(source=2, blend=2)
        held.clear()
        edges.clear()
        clicks.clear()
        if space:
            held.add(0x39)
        if esc:
            edges.add(1)
        if enter:
            edges.add(0x1C)
        if click:
            clicks.add(0)
        pe.write_f32(clock, 4 + age + 0.125 * tick)
        calls.clear()
        assert pe.call(routine).eax & 255 == 1
        expected = [pe.read_f32(dt), pe.read_f32(since), pe.read_f32(alpha), pe.read_u8(pending), pe.read_u8(opened)]
        assert all(math.isclose(a, b, abs_tol=1e-6) for a, b in zip(expected, result, strict=True)), (
            edition,
            args,
            expected,
        )
        for call in calls:
            row = next(rows)
            for item, actual in zip(call, row, strict=True):
                if isinstance(item, str):
                    assert item == actual, (edition, age, call, row)
                else:
                    assert math.isclose(item, float(actual), rel_tol=1e-6, abs_tol=0.0003), (edition, age, call, row)
        frames += 1
        draws += len(calls)
    assert frames == 12
    print(f"{edition}: {draws} original credits draws across {frames} scroll and dismissal frames matched")
