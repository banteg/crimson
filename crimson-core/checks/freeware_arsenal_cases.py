"""Weapon and perk comparisons against the historical x86 executables."""

import math
import struct

from crimson_re.dbg.native_oracle import NativeOracle, SymbolTable


def original(exe, early):
    pe = NativeOracle(exe, symbols=SymbolTable({}), rand_state_address=0x41DCC8 if early else 0x42B634)
    table = pe.alloc(512)
    pe.write_u32(0x4287EC if early else 0x447754, pe.alloc(4, data=struct.pack("<I", table)))
    samples = []
    mouse = 0x40 if early else 0x48
    for offset in [0x38, 0x3C, mouse, 0x44, 0x6C] if early else [0x40, 0x44, mouse, 0x4C, 0x88]:
        fn = pe.load_code(b"\xc3")
        pe.stub(fn, (lambda c: int(c.arg_u32(0) == 0)) if offset == mouse else 0, pop=4)
        pe.write_u32(table + offset, fn)
    # Leave original data pointers in place in the metadata table instead of allocating wrapped UI strings.
    pe.stub(0x401C10 if early else 0x404A60, lambda c: c.arg_u32(0))
    pe.call(0x401C80 if early else 0x404AD0)
    pe.stub(0x401630 if early else 0x403000, lambda c: samples.append(c.arg_u32(0)) or 0)
    if not early:
        pe.write_u32(0x433F10, pe.alloc(160))
    for addr in [0x41C0BC, 0x41C0C0] if early else [0x429100, 0x429104]:
        pe.write_u32(addr, 1024)
    pe.call(0x402230 if early else 0x405300)
    return pe, samples


def floats(actual, expected, case):
    assert len(actual) == len(expected), (case, actual, expected)
    assert all(math.isclose(a, b, rel_tol=1e-6, abs_tol=5e-5) for a, b in zip(actual, expected, strict=True)), (
        case,
        actual,
        expected,
    )


def check_weapons(exe, edition, lines):
    early = edition == "1.0.2"
    pe, sounds = original(exe, early)
    if early:
        # Clip assignment embedded in player_render; 0x40791e is the common pickup cleanup.
        pe.stub(0x40791E, 0)
    initial = pe.snapshot()
    events = iter(line.split() for line in lines if line.startswith(("arm ", "fire ", "round ")))
    cases = 0
    for header in events:
        assert header[0] == "arm", header
        _, weapon, who, clip, *name = header
        weapon, who = int(weapon), int(who)
        pe.restore(initial)
        shift = who * 328
        wid = 0x421F8C if early else 0x4300AC + shift
        rounds = 0x421EE8 if early else 0x42FFFC + shift
        if early:
            pe.write_u32(wid, weapon)
            if weapon != 17:
                pe.call(0x40778C, regs={"eax": 0})
                assert pe.read_f32(rounds) == float(clip)
        else:
            pe.call(0x403C00, who, weapon)
            assert pe.read_f32(rounds) == float(clip)
            ptr = pe.call(0x404120, weapon).eax
            assert pe.read(ptr, 64).split(b"\0", 1)[0].decode() == " ".join(name)
        _, wid_str, variant, seed, ammo, cooldown, reload, spread, flash, rng, *samples = next(events)
        variant = int(variant)
        assert int(wid_str) == weapon
        if not early:
            pe.write_u32(0x44774C, who)
            pe.write_u32(0x4374A8, who + 1)
            pe.write_u32(0x4374B4 + who * 4, 2)
            pe.write_u32(0x4374BC + who * 4, 0)
        for addr, value in [
            (0x41C080 if early else 0x4290B4, 1),
            (0x428884 if early else 0x447828, 1 / 60),
            (0x4220F0 if early else 0x430288, 712),
            (0x4220F4 if early else 0x43028C, 512),
            (0x421E9C if early else 0x42FFA8 + shift, 512),
            (0x421EA0 if early else 0x42FFAC + shift, 512),
            (0x421F00 if early else 0x43001C + shift, 0),
            (rounds, 0.04 if variant == 1 else 10),
        ]:
            pe.write_f32(addr, value)
        if variant == 1:
            for key in [0x428834, 0x428818, 0x428820] if early else [0x4477B0, 0x447798, 0x4477A0, 0x4477D0]:
                pe.write_u32((0x421F04 if early else 0x430024 + shift) + 4 * pe.read_u32(key), 1)
        pe.rand_state = int(seed)
        sounds.clear()
        pe.call(0x408040 if early else 0x40E430)
        case = edition, weapon, variant
        addrs = (
            [0x421EE8, 0x421F00, 0x421EEC, 0x421F84, 0x421F98]
            if early
            else [
                0x42FFFC + shift,
                0x43001C + shift,
                0x430000 + shift,
                0x4300A4 + shift,
                0x4300B8 + shift,
            ]
        )
        floats([pe.read_f32(addr) for addr in addrs], list(map(float, (ammo, cooldown, reload, spread, flash))), case)
        assert sounds == list(map(int, samples)) and pe.rand_state == int(rng), (
            case,
            sounds,
            samples,
            pe.rand_state,
            rng,
        )
        pools = [("b", 0x422128 if early else 0x4307D0, 48 if early else 52, 64, 32, (8, 12, 4, 44))]
        if not early:
            pools.append(("r", 0x432EF0, 40, 64, 28, (12, 16, 4, 8)))
        pools.append(
            ("f", 0x422D28 if early else 0x4314D0, 48 if early else 52, 128, 1 if early else 48, (4, 8, 40, 36)),
        )
        for kind, base, stride, count, type_offset, fields in pools:
            for slot in range(count):
                addr = base + stride * slot
                if not pe.read_u8(addr):
                    continue
                tag, pool, typ, *values = next(events)
                native_type = pe.read_u8(addr + type_offset) if kind == "f" else pe.read_u32(addr + type_offset)
                assert (tag, pool, int(typ)) == ("round", kind, native_type), (case, pool, typ, native_type)
                floats([pe.read_f32(addr + off) for off in fields], list(map(float, values)), (case, kind, slot))
        cases += 1
    assert cases == (27 if early else 51), cases
    print(f"{edition}: {cases} original weapon volleys, ammo, reload, sound, trajectories and RNG matched")


def check_hits(exe, edition, lines):
    early = edition == "1.0.2"
    pe, _ = original(exe, early)
    baseline = pe.snapshot()
    cases = 0
    for line in lines:
        if not line.startswith("impact "):
            continue
        _, typ, mode, x, y, life, hp, infected, rng = line.split()
        mode, typ = int(mode), int(typ)
        pe.restore(baseline)
        pe.rand_state = 87
        pe.write_f32(0x428884 if early else 0x447828, 1 / 60)
        pe.write_u32(0x41C0A0 if early else 0x4374B0, 2)
        pe.write_f32(0x428804 if early else 0x447778, 2 if mode == 2 else 0)
        if early:
            pe.write_u32(0x41C0CC, 0)
        pool = 0x4252D0 if early else 0x4374F8
        pe.write_u8(pool, int(mode != 0))
        for offset, val in (
            (12 if early else 24, 110),
            (16 if early else 28, 100),
            (28 if early else 40, 1000),
            (8 if early else 20, 16),
            (36 if early else 52, 42),
        ):
            pe.write_f32(pool + offset, val)
        pe.call(0x402B70 if early else 0x4060D0, pe.alloc_f32s(100, 100), 1.57079637, typ)
        shot = 0x422128 if early else 0x4307D0
        pe.write_f32(shot + 16, 13)
        pe.call(0x402CA0 if early else 0x406260)
        case = edition, typ, mode
        floats(
            [pe.read_f32(shot + off) for off in (8, 12, 36)] + [pe.read_f32(pool + (28 if early else 40))],
            list(map(float, (x, y, life, hp))),
            case,
        )
        assert pe.read_u8(pool + (1 if early else 12)) == int(infected), case
        assert pe.rand_state == int(rng), (case, "impact RNG", pe.rand_state, rng)
        cases += 1
    assert cases == (15 if early else 21)
