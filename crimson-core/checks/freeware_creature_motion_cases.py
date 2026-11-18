"""Run original creature pursuit and contact ticks from the same initial conditions as each client."""

import math
import struct

from freeware_arsenal_cases import original


def check_creature_motion(exe, edition, lines):
    early = edition == "1.0.2"
    pe, _ = original(exe, early)
    base = pe.snapshot()
    pool, stride = (0x4252D0, 104) if early else (0x4374F8, 128)
    player, pstride = (0x421E9C, 268) if early else (0x42FFA8, 328)
    blood_count, blood = (0x428870, 0x4245C0) if early else (0x447814, 0x433A08)
    # Offsets from each native creature base, following the row emitted by the shared client.
    # The first edition has no retargeting, activation radius, clone timer or target heading fields.
    offsets = (
        (0, 12, 16, 20, 24, 28, 32, 36, 68, 72, 76, 100, 8, 60, 64, 4, 1, 56, None, None, None, None, None)
        if early
        else (0, 24, 28, 32, 36, 40, 44, 52, 84, 88, 92, 124, 20, 76, 80, 16, 12, 72, 120, 1, 4, 8, 48)
    )
    formats = "B" + "f" * 15 + "BBiBfff"
    steps = 0
    for line in lines:
        if not line.startswith("motion"):
            continue
        tag, *args = line.split()
        if tag == "motioncase":
            n, mode, players, active, berserk, freeze, reserved, spawned, wall_present = map(float, args)
            pe.restore(base)
            pe.write_u32(0x41C0A0 if early else 0x4374B0, int(mode))
            pe.write_f32(0x428808 if early else 0x44777C, freeze)
            pe.write_f32(0x428854 if early else 0x4477F0, berserk)
            if not early:
                pe.write_u8(0x447774, int(active))
                pe.write_u32(0x4374A8, int(players))
                pe.write_u32(0x430024 + 22 * 4, int(reserved))
                if wall_present:
                    level = pe.read_u32(0x433F10)
                    wall = pe.alloc(48, data=struct.pack("<5f", 522, 480, 0, 12, 90) + bytes(28))
                    walls = pe.alloc(4, data=struct.pack("<I", wall))
                    pe.write(level + 0x28, struct.pack("<2I", walls, walls + 4))
            pe.rand_state = 76
            pe.write_u32(0x428868 if early else 0x44780C, int(spawned))
        elif tag == "motionplayer":
            index, x, y, hp, shield = map(float, args)
            addr = player + int(index) * pstride
            pe.write(addr, struct.pack("<2f", x, y))
            pe.write_f32(addr + 16, hp)
            if not early:
                pe.write_f32(addr + 0x120, shield)
        elif tag == "motionrow":
            tick, slot = map(int, args[:2])
            addr = pool + slot * stride
            for offset, fmt, value in zip(offsets, formats, args[2:], strict=True):
                if offset is None:
                    continue
                val = float(value) if fmt == "f" else int(value)
                if tick == -1:
                    pe.write(addr + offset, struct.pack("<" + fmt, val))
                else:
                    want = struct.unpack("<" + fmt, pe.read(addr + offset, struct.calcsize(fmt)))[0]
                    assert math.isclose(val, want, rel_tol=2e-6, abs_tol=1e-4), (
                        edition,
                        n,
                        tick,
                        slot,
                        offset,
                        val,
                        want,
                    )
        elif tag == "motionstep":
            tick, dt, x, y, hp, hp2, marks, spawned, rng = map(float, args)
            pe.write(player, struct.pack("<2f", x, y))
            pe.write_f32(0x428884 if early else 0x447828, dt)
            pe.write_f32(0x428888 if early else 0x447720, 1 + tick * 0.125)
            pe.call(0x404B70 if early else 0x409C80)
            actual = (
                pe.read_f32(player + 16),
                pe.read_f32(player + pstride + 16),
                pe.read_u32(blood_count),
                pe.read_u32(0x428868 if early else 0x44780C),
                pe.rand_state,
            )
            assert actual == (hp, hp2, marks, spawned, rng), (edition, n, tick, actual, args)
            steps += 1
        elif tag == "motionmark":
            index, x, y = map(float, args)
            coords = struct.unpack("<2f", pe.read(blood + 8 * int(index), 8))
            assert all(math.isclose(a, b, abs_tol=0.0002) for a, b in zip(coords, (x, y), strict=True)), (
                edition,
                n,
                tick,
                index,
                coords,
                (x, y),
            )
    assert steps == (80 if early else 150)
    print(f"{edition}: {steps} original creature pursuit, contact and retirement ticks matched")
