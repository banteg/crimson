"""Compare 1.3.0 weapon acquisition through the original pickup, file loader and level trigger."""

import io
import struct

from freeware_arsenal_cases import original


def prepare_weapon_maps(install, tmp):
    # Keep every byte of the shipped level 2 except its single AutoRifle grant.
    data = bytearray((install / "levels/level_2.lvl").read_bytes())
    count = struct.unpack_from("<I", data, 41)[0]
    triggers = [pos for pos in range(57, 57 + 40 * count, 40) if struct.unpack_from("<I", data, pos)[0] == 2]
    (trigger,) = triggers
    assert struct.unpack_from("<I", data, trigger + 32)[0] == 2
    for weapon in (16, 17):
        folder = tmp / "weapon-tests" / str(weapon) / "levels"
        folder.mkdir(parents=True)
        struct.pack_into("<I", data, trigger + 32, weapon)
        (folder / "level_5.lvl").write_bytes(data)


def check_pickups(pe, lines):
    pe.write_u32(0x4374A8, 2)
    pe.write_u32(0x4374B0, 1)
    pos = pe.alloc_f32s(512, 512)
    offered = set()
    cases = [(seed, seed % 2, 1) for seed in range(1, 129)] + [(12, 1, 2)]
    rows = [line.split()[1:] for line in lines if line.startswith("weaponpickup ")]
    for (seed, who, held), row in zip(cases, rows, strict=True):
        offset = who * 328
        pe.write_u32(0x44774C, who)
        pe.write(0x42FFA8 + offset, pe.read(pos, 8))
        pe.call(0x403C00, who, held)
        pe.rand_state = seed
        pe.call(0x403EE0, pos)
        rolled = pe.read_u32(0x4477FC)
        assert pe.read_u32(0x430274) == pe.read_u32(0x4290EC) and rolled != held
        # Collection is part of player_render. Enter after drawing and stop after the pickup sound.
        pe.run(0x40CB0D, 0x40CC80)
        weapon = pe.read_u32(0x4300AC + offset)
        assert weapon == rolled
        expected = (
            seed,
            who,
            held,
            weapon,
            pe.read_f32(0x42FFFC + offset),
            pe.read_f32(0x4300B4 + offset),
            pe.rand_state,
        )
        assert tuple(map(float, row)) == expected, (expected, row)
        offered.add(weapon)
    assert offered == set(range(2, 16))


def mount_level_files(pe, level_folder):
    handle = pe.alloc(4)
    stream = io.BytesIO()

    def fopen(call):
        nonlocal stream
        filename = pe.read(call.arg_u32(0), 64).split(b"\0", 1)[0].decode().replace("\\", "/")
        path = level_folder() / filename
        if not path.exists():
            return 0
        stream = io.BytesIO(path.read_bytes())
        return handle

    def fread(call):
        size, count = call.arg_u32(1), call.arg_u32(2)
        data = stream.read(size * count)
        assert len(data) == size * count, "short read from numbered map"
        pe.write(call.arg_u32(0), data)
        return count

    pe.stub(0x41BF73, fopen)
    pe.stub(0x41BE6B, fread)
    pe.stub(0x41BE15, 0)  # fclose
    pe.stub(0x41BC48, 0)  # CRT free, paired with the oracle allocator


def check_acquisition(install, tmp, lines):
    pe, _ = original(install / "crimson.exe", False)
    check_pickups(pe, lines)
    level = pe.read_u32(0x433F10)
    pe.write_u32(0x4374A8, 1)
    pe.write_u32(0x4374B0, 3)
    pe.write_u32(0x44774C, 0)
    mount_level_files(pe, lambda: folder)
    pe.stub(0x40A3C0, 0)  # terrain drawing
    baseline = pe.snapshot()
    expected = []
    maps = [(0, n) for n in range(1, 6)] + [(16, 5), (17, 5)]
    for custom, requested in maps:
        pe.restore(baseline)
        folder = tmp / "weapon-tests" / str(custom) if custom else install
        pe.write_u32(0x44782C, requested - 1)
        pe.call(0x411610)  # Select filename, load the map, reset both pistols and arm triggers.
        start, end = struct.unpack("<2I", pe.read(level + 0x48, 8))
        triggers = [pe.read_u32(ptr) for ptr in range(start, end, 4)]
        grants = [t for t in triggers if pe.read_u32(t) == 2]
        loaded = pe.read_u32(0x44782C)
        weapons = [pe.read_u32(t + 32) for t in grants]
        assert weapons == ([custom or 2] if custom or loaded in (2, 3) else []), (loaded, weapons)
        expected.append(("mapweapons", custom, requested, loaded, *weapons))
        for t in grants:
            for step in range(3):
                pe.write_f32(0x42FFA8, pe.read_f32(t + 8) + pe.read_f32(t + 28) - int(step != 0))
                pe.write_f32(0x42FFAC, pe.read_f32(t + 12))
                if step == 2:
                    pe.write_f32(0x42FFFC, pe.read_f32(0x42FFFC) - 0.5)
                pe.call(0x4020C0, ecx=level)
                expected.append(
                    (
                        "mapgrant",
                        custom,
                        requested,
                        step,
                        pe.read_u32(0x4300AC),
                        pe.read_f32(0x42FFFC),
                        pe.read_f32(0x4300B4),
                        pe.read_u8(t + 4),
                    ),
                )
    actual = [line.split() for line in lines if line.startswith(("mapweapons ", "mapgrant "))]
    for want, (tag, *values) in zip(expected, actual, strict=True):
        assert (tag, *map(float, values)) == want, (want, tag, values)
    print("1.3.0: original weapon pickups (IDs 2–15), numbered maps and custom grants of IDs 16 and 17 matched")
