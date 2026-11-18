"""Weapon and perk comparisons against the historical x86 executables."""

import math
import struct

from crimson_re.dbg.native_oracle import NativeOracle, SymbolTable


def original(exe, early, keys=(), buttons=(0,)):
    pe = NativeOracle(exe, symbols=SymbolTable({}), rand_state_address=0x41DCC8 if early else 0x42B634)
    table = pe.alloc(512)
    pe.write_u32(0x4287EC if early else 0x447754, pe.alloc(4, data=struct.pack("<I", table)))
    samples = []
    mouse = 0x40 if early else 0x48
    for offset in [0x38, 0x3C, mouse, 0x44, 0x6C] if early else [0x40, 0x44, mouse, 0x4C, 0x88]:
        fn = pe.load_code(b"\xc3")
        if offset == mouse:
            pe.stub(fn, lambda c: int(c.arg_u32(0) in buttons), pop=4)
        elif offset == mouse - 8:
            pe.stub(fn, lambda c: int((c.arg_u32(0) & 255) in keys), pop=4)
        else:
            pe.stub(fn, 0, pop=4)
        pe.write_u32(table + offset, fn)
    # Let the original wrap its registered text. Only the CRT allocator and graphics lookup are host services.
    pe.stub(0x410F9E if early else 0x41BE07, lambda c: pe.alloc(c.arg_u32(0)))
    if not early:
        pe.call(0x401350)
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
            # The HUD draws these literals in its 0x40e235 switch; ID 17 takes the default.
            labels = (0x41D438, 0x41D42C, 0x41D424, 0x41D414, 0x41D404, 0x41D3F4, 0x41D3D8, 0x41D3C8)
            label = labels[weapon - 1] if weapon <= 8 else 0x41D3C0
            assert pe.read(label, 64).split(b"\0", 1)[0].decode() == " ".join(name)
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
        _, typ, mode, x, y, life, hp, infected, rng, death, creatures, xp, drop, drop_x, drop_y, drop_time = line.split()
        mode, typ = int(mode), int(typ)
        pe.restore(baseline)
        survival = mode >= 5
        pe.rand_state = 3 if survival else 87
        pe.write_f32(0x428884 if early else 0x447828, 1 / 60)
        pe.write_u32(0x41C0A0 if early else 0x4374B0, 1 if survival else 2)
        if survival:
            pe.write_u32(0x421EF8, 31)
            pe.write_u32(0x421F8C, 1)
            if mode == 6:
                pe.write_u32(0x4220E8, 1)
                pe.write(0x420B88, struct.pack("<ff", 79, 81))
                pe.write_f32(0x42885C, 3.5)
        pe.write_f32(0x428804 if early else 0x447778, 2 if mode == 2 else 0)
        if early:
            pe.write_u32(0x41C0CC, 0)
        pe.write_f32(0x428808 if early else 0x44777C, 1 if mode == 4 else 0)
        pe.write_u32(0x428868 if early else 0x44780C, int(mode != 0))
        pool = 0x4252D0 if early else 0x4374F8
        pe.write(pool + (80 if early else 96), struct.pack("<i" if early else "<d", 121))
        pe.write_u8(pool, int(mode != 0))
        for offset, val in (
            (12 if early else 24, 110),
            (16 if early else 28, 100),
            (28 if early else 40, 1000 if mode < 3 else 5),
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
        floats([pe.read_f32(pool + (8 if early else 20))], [float(death)], (case, "death timer"))
        assert pe.read_u32(0x428868 if early else 0x44780C) == int(creatures) & 0xFFFFFFFF, (case, creatures)
        assert pe.read_u32(0x421EF8 if early else 0x430010) == int(xp), (case, xp)
        assert pe.rand_state == int(rng), (case, "impact RNG", pe.rand_state, rng)
        if survival:
            assert pe.read_u32(0x4220E8) == int(drop), (case, "pickup kind")
            floats(
                [pe.read_f32(addr) for addr in (0x420B88, 0x420B8C, 0x42885C)],
                list(map(float, (drop_x, drop_y, drop_time))),
                (case, "pickup position and time"),
            )
        cases += 1
    assert cases == (27 if early else 35)


def check_perks(exe, edition, lines):
    early = edition == "1.0.2"
    pe, _ = original(exe, early)
    count = 16 if early else 22
    stacks = 0x421F04 if early else 0x430024
    flags = 0x424588 if early else 0x433910
    xp = 0x421EF8 if early else 0x430010
    level = 0x421EFC if early else 0x430018
    hp = 0x421EAC if early else 0x42FFB8
    pending = 0x428860 if early else 0x447804
    # Enter at the first instruction after the original picker accepts a click.
    # Stop at its register-restoring epilogue, after the co-op stack copy.
    pe.stub(0x40BCF4 if early else 0x411607, 0)
    baseline = pe.snapshot()
    seen = {"meta": 0, "grant": 0, "choice": 0, "level": 0}
    for line in lines:
        tag, *args = line.split()
        if tag not in seen:
            continue
        seen[tag] += 1
        pe.restore(baseline)
        case = edition, line
        if tag == "meta":
            i, name, description = args
            addr = 0x424BC8 + int(i) * 16 if early else 0x436D18 + int(i) * 20
            for offset, val in [(0, name), (4, description)]:
                text = pe.read(pe.read_u32(addr + offset), 512).split(b"\0", 1)[0]
                assert text == bytes.fromhex(val), (edition, i, text)
        elif tag == "grant":
            i, coop, playing, lv, experience, health, left, owned, partner, plague = map(float, args)
            pe.write_u32(0x4287F8 if early else 0x447768, int(i))
            pe.write_u32(xp, 800)
            pe.write_u32(level, 4)
            pe.write_u32(pending, 2)
            pe.write_f32(hp, 60)
            if not early:
                pe.write_u32(0x4374A8, int(coop) + 1)
            pe.call(0x40BC44 if early else 0x4114E5, regs={"ebx": 0})
            assert int(playing) and pe.read_u32(0x41C09C if early else 0x4290D4) == 3, case
            assert [pe.read_u32(a) for a in (level, xp, pending)] == [lv, experience, left], case
            floats([pe.read_f32(hp)], [health], case)
            assert pe.read_u8(0x421E91 if early else 0x42FF9C) == plague, case
            for base, mask in ((stacks, int(owned)), (stacks + (268 if early else 328), int(partner))):
                assert [pe.read_u32(base + j * 4) for j in range(count)] == [(mask >> j) & 1 for j in range(count)], (
                    case
                )
        elif tag == "choice":
            seed, coop, mix, owned, choices, rng = map(int, args)
            if not early:
                pe.write_u32(0x4374A8, coop + 1)
            for j in range(count):
                pe.write_u32(stacks + j * 4, mix if not early and j == 21 else (owned >> j) & 1)
            pe.rand_state = seed
            pe.call(0x402900 if early else 0x405BB0)
            assert sum(1 << j for j, b in enumerate(pe.read(flags, 32)) if b) == choices, case
            assert pe.rand_state == rng, case
        else:
            before, experience, after, left, choices, rng, active, health, reward = map(float, args)
            pe.write_u32(level, int(before))
            pe.write_u32(xp, int(experience))
            pe.write_u32(0x41C0A0 if early else 0x4374B0, 1)
            pe.write_u8(0x4287F6 if early else 0x447764, 1)
            pe.rand_state = 123
            pe.call(0x402350 if early else 0x4054C0)
            addr = 0x4252D0 if early else 0x4374F8
            assert (pe.read_u32(level), pe.read_u32(pending), pe.rand_state, pe.read_u8(addr)) == (
                after,
                left,
                rng,
                active,
            ), case
            assert sum(1 << j for j, b in enumerate(pe.read(flags, 32)) if b) == choices, case
            native_xp = pe.read_u32(addr + 80) if early else struct.unpack("<d", pe.read(addr + 96, 8))[0]
            assert pe.read_f32(addr + (28 if early else 40)) == health and native_xp == reward, case
    # At rest there are no shot, spawn or camera rolls on the frame opening the picker.
    live = [line.split() for line in lines if line.startswith("livepick ")]
    assert len(live) == 3
    for _, seed, picking, mask, rng in live:
        pe.restore(baseline)
        if not early:
            pe.write_u32(0x4374A8, 1)
        pe.rand_state = int(seed)
        pe.call(0x402900 if early else 0x405BB0)
        assert int(picking) and pe.rand_state == int(rng), (edition, seed, rng, pe.rand_state)
        assert sum(1 << j for j, b in enumerate(pe.read(flags, 32)) if b) == int(mask), (edition, seed, mask)
    assert seen == {"meta": count, "grant": count * (1 if early else 2), "choice": 18 if early else 36, "level": 12}
    print(
        f"{edition}: {seen['meta']} perk records, {seen['grant']} grants, {seen['choice']} drafts and 12 level checks matched",
    )


def check_flight(exe, edition, lines):
    early = edition == "1.0.2"
    pe, _ = original(exe, early)
    baseline = pe.snapshot()
    shot_pool, shot_stride = (0x422128, 48) if early else (0x4307D0, 52)
    flame_pool, flame_stride = (0x422D28, 48) if early else (0x4314D0, 52)
    for base, stride, size in ((shot_pool, shot_stride, 64), (flame_pool, flame_stride, 128)):
        for i in range(size):
            pe.write_u8(base + i * stride, 1)
    pe.rand_state = 77
    pos = pe.alloc_f32s(200, 250)
    shot = pe.call(0x402B70 if early else 0x4060D0, pos, 0.5, 4).eax
    flame = pe.call(0x402A90 if early else 0x405EE0, pos, 0.5, pe.alloc_f32s(0, 0), 1.0).eax
    assert f"overflow {shot} {flame} {pe.rand_state}" in lines
    count = 0
    for line in lines:
        if not line.startswith("flight "):
            continue
        _, kind, hit, tick, typ, x, y, angle, life, hp, cx, rng = line.split()
        kind = int(kind)
        rocket = kind in (11, 12)
        c = 0x4252D0 if early else 0x4374F8
        shot = 0x432EF0 if rocket else 0x422D28 if early else 0x4314D0
        if tick == "0":
            pe.restore(baseline)
            pe.write_f32(0x428884 if early else 0x447828, 1 / 60)
            pe.write_u32(0x41C0A0 if early else 0x4374B0, 2)
            pe.write_u8(c, 1)
            for offset, val in (
                (12 if early else 24, 109 if hit == "1" else 420),
                (16 if early else 28, 100),
                (28 if early else 40, 3000),
                (8 if early else 20, 16),
                (36 if early else 52, 42),
            ):
                pe.write_f32(c + offset, val)
            pe.write(c + (40 if early else 56), struct.pack("<4f", 1, 1, 1, 1))
            pe.rand_state = 14
            pos = pe.alloc_f32s(100, 100)
            if rocket:
                pe.call(0x405FF0, pos, 1.57079637, kind - 10)
                # As in the playing callback after the first hit, the combat track is active.
                pe.stub(0x403000, 0)
            else:
                pe.call(0x402A90 if early else 0x405EE0, pos, 0.0, pe.alloc_f32s(0, 0), 1.0)
                if not early:
                    pe.write_u8(shot + 48, int(kind == 15))
        pe.call(0x402CA0 if early else 0x406260)
        case = edition, kind, hit, tick
        assert (pe.read_u32(shot + 28) if rocket else pe.read_u8(shot + 1)) == int(typ), case
        fields = [pe.read_f32(shot + off) for off in ((12, 16, 4, 8) if rocket else (4, 8, 40, 36))]
        fields.extend(pe.read_f32(c + off) for off in ((28, 12) if early else (40, 24)))
        floats(fields, list(map(float, (x, y, angle, life, hp, cx))), case)
        assert pe.rand_state == int(rng), (case, pe.rand_state, rng)
        count += 1
    assert count == (16 if early else 64)


def check_player_perks(exe, edition, lines):
    early = edition == "1.0.2"
    keys = set()
    buttons = set()
    pe, _ = original(exe, early, keys, buttons)
    base = pe.snapshot()
    count = 0
    for line in lines:
        if not line.startswith("playerperk "):
            continue
        _, scenario, xp, x, y, speed, heading, cooldown, scale, rng = line.split()
        n = int(scenario)
        pe.restore(base)
        keys.clear()
        buttons.clear()
        if n <= 3:
            keys.add(0x11)
        if n in (4, 6, 7, 8):
            buttons.add(1)
        if early:
            pe.write_u32(0x41C094, 1)
        else:
            pe.write_u32(0x4374A8, 1)
            pe.write_u32(0x4374B4, 1)
            pe.write_u8(0x4300CC, 0x11)
        pe.write_u32(0x41C0A0 if early else 0x4374B0, 2 if n == 8 else 1)
        pe.write_u32(0x421EF8 if early else 0x430010, 0 if n == 6 else 1500)
        stacks = 0x421F04 if early else 0x430024
        pe.write_u32(stacks + 3 * 4, int(n < 3))
        if early:
            pe.write_u32(stacks + 11 * 4, int(n in (4, 5, 6)))
        for addr, value in [
            (0x421EB0 if early else 0x42FFBC, 0.5),
            (0x421EE4 if early else 0x42FFF8, 1.98 if n == 1 else 3.95 if n == 2 else 0),
            (0x421F00 if early else 0x43001C, 0 if n == 9 else 0.5),
            (0x41C080 if early else 0x4290B4, 0.32 if n == 4 else 0.9),
            (0x428884 if early else 0x447828, 0.1),
            (0x428888 if early else 0x447720, 0.75),
            (0x428854 if early else 0x4477F0, 12 if n == 9 else 0),
            (0x4220F0 if early else 0x430288, 712),
            (0x4220F4 if early else 0x43028C, 512),
            (0x421ECC if early else 0x42FFDC, 712),
            (0x421ED0 if early else 0x42FFE0, 512),
        ]:
            pe.write_f32(addr, value)
        pe.rand_state = 123
        pe.call(0x408040 if early else 0x40E430)
        case = edition, n
        assert pe.read_u32(0x421EF8 if early else 0x430010) == int(xp) & 0xFFFFFFFF, case
        addrs = (
            (0x421E9C, 0x421EA0, 0x421EE4, 0x421EB0, 0x421F00, 0x41C080)
            if early
            else (0x42FFA8, 0x42FFAC, 0x42FFF8, 0x42FFBC, 0x43001C, 0x4290B4)
        )
        floats([pe.read_f32(addr) for addr in addrs], list(map(float, (x, y, speed, heading, cooldown, scale))), case)
        assert pe.rand_state == int(rng), (case, pe.rand_state, rng)
        count += 1
    assert count == (10 if early else 5)


def check_creature_perks(exe, edition, lines):
    early = edition == "1.0.2"
    pe, _ = original(exe, early)
    base = pe.snapshot()
    count = 0
    for line in lines:
        if not line.startswith("creatureperk "):
            continue
        _, n, hp, death, phase, tx, ty, infected, infections, earned, rng = line.split()
        n = int(n)
        pe.restore(base)
        pe.write_u32(0x41C0A0 if early else 0x4374B0, 2)
        pe.write_u32(0x428868 if early else 0x44780C, 1)
        pe.write_u32(0x421EF8 if early else 0x430010, 500)
        pe.write_f32(0x428884 if early else 0x447828, 0.1)
        pe.write_f32(0x428888 if early else 0x447720, 0.75)
        stacks = 0x421F04 if early else 0x430024
        pe.write_u32(stacks + 4, int(n == 1))
        pe.write_u32(stacks + (9 if early else 11) * 4, int(n == 2))
        pe.write_u8(0x421E91 if early else 0x42FF9C, int(n in (3, 4)))
        c = 0x4252D0 if early else 0x4374F8
        pe.write_u8(c, 1)
        pe.write_u8(c + (1 if early else 12), int(n >= 5))
        if not early:
            pe.write_f32(c + 8, -1)
        pe.write(c + (80 if early else 96), struct.pack("<i" if early else "<d", 121))
        for off, value in (
            (12 if early else 24, 528 if n in (3, 4) else 575),
            (16 if early else 28, 512),
            (28 if early else 40, 200 if n == 4 else 2 if n == 6 else 80),
            (8 if early else 20, 16),
            (36 if early else 52, 48),
            (76 if early else 92, 1),
        ):
            pe.write_f32(c + off, value)
        pe.rand_state = 76
        pe.call(0x404B70 if early else 0x409C80)
        case = edition, n
        fields = (28, 8, 4, 60, 64) if early else (40, 20, 16, 76, 80)
        floats([pe.read_f32(c + off) for off in fields], list(map(float, (hp, death, phase, tx, ty))), case)
        assert pe.read_u8(c + (1 if early else 12)) == int(infected), case
        assert (0 if early else pe.read_u32(0x447750)) == int(infections), case
        assert pe.read_u32(0x421EF8 if early else 0x430010) == int(earned), case
        assert pe.rand_state == int(rng), (case, pe.rand_state, rng)
        count += 1
    assert count == 7
