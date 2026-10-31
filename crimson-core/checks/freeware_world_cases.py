"""Run the released world renderers with the same pools and capture ordered Grim submissions."""

import ctypes
import math
import struct

from freeware_ui_cases import UiOracle


def check_world(check, exe):
    original = UiOracle(exe)
    pe = original.pe
    original.textures[701] = "goblin"
    pe.write_u32(0x452D2C, 701)
    pe.call(0x408DC0)  # Original 8x8 atlas initializer.
    total = 0
    for flags in range(4):
        check.dll.combat_world_start(flags)
        pe.write_f32(0x43CBC0, -27.5)
        pe.write_f32(0x43CBC4, 11.25)
        pe.write_u8(0x44289B, flags & 1)
        pe.write_f32(0x452DBC, 2 if flags & 2 else 0)
        pe.write(0x442AF8, bytes(512 * 128))
        for addr in (0x4387F8, 0x452E80, 0x452E88):
            pe.write_u32(addr, 0)
        for i, (kind, animation, death, infected) in enumerate(
            [(0, 4, 16, 0), (1, 18, 16, 1), (0, 19.5, 16, 0), (1, 15.45, 6.5, 0), (0, 4, -0.25, 0), (1, 4, -2.375, 1)],
        ):
            slot = (0, 1, 19, 63, 220, 511)[i]
            record = bytearray(128)
            record[0] = 1
            record[12] = infected
            for offset, value in (
                (20, death),
                (24, 140.5 + i * 11),
                (28, 81.25 - i),
                (44, 0.5 + i / 8),
                (52, 28 + i * 3),
                (56, 0.3),
                (60, 0.7),
                (64, 0.9),
                (68, 0.625),
                (124, animation),
            ):
                struct.pack_into("<f", record, offset, value)
            struct.pack_into("<i", record, 116, kind)
            data = bytes(record)
            pe.write(0x442AF8 + slot * 128, data)
            ctypes.memmove(check.symbol("creature_pool") + slot * 128, data, 128)
        for frame in range(2):
            original.reset_draw()
            pe.call(0x40FD10)
            n = check.dll.combat_world_render(0)
            total += original.compare(check, n, ("creatures", flags, frame))
            state = (ctypes.c_float * 24).from_address(check.symbol("combat_world_state"))
            assert tuple(state[:3]) == tuple(pe.read_i32(a) for a in (0x4387F8, 0x452E80, 0x452E88))
            last = pe.read_i32(0x452E88) - 1
            expected = (
                pe.read_f32(0x436AF8 + 8 * last),
                pe.read_f32(0x436AFC + 8 * last),
                pe.read_f32(0x438378 + 4 * last),
                pe.read_f32(0x43C8B4 + 4 * last),
                62 if pe.read_i32(0x442390 + 4 * last) else 31,
            )
            assert all(math.isclose(a, b, abs_tol=0.0001) for a, b in zip(state[3:8], expected, strict=True))
            assert ctypes.string_at(check.symbol("creature_pool"), 512 * 128) == pe.read(0x442AF8, 512 * 128)
    return (
        total
        + check_player_draws(check, original)
        + check_effect_draws(check, original)
        + check_terrain_draws(check, original)
        + check_fx_queue(check, original)
    )


def check_player_draws(check, original):
    pe = original.pe
    original.textures[702] = "ugluk"
    pe.write_u32(0x43831C, 702)
    pe.stub(0x405630, 0)
    pe.write_u32(0x452E10, 12)
    pe.write_u32(0x452DE8, 2)
    total = 0
    for i in range(27):
        slot = i % 2
        count = 2 if slot or i % 4 else 1
        kind = i % 7
        distance = (31, 32, 33)[i // 7 % 3]
        check.dll.combat_world_start(0)
        data = bytearray(0x310)
        for j in range(2):
            offset = j * 0x188
            for field, value in (
                (0x18, 235.5 + 100 * j),
                (0x1C, 97.25 - 32 * j),
                (0x28, 0 if i == 26 else 71),
                (0x2C, 2.55),
                (0x34, 46.5),
                (0x6C, 3),
                (0x7C, (0, 7.25, 14.8)[i % 3]),
                (0x8C, 0.625),
                (0x164, 17),
                (0x168, 0.245 if i % 2 else 0),
                (0x16C, -1.123),
                (0x178, (0, 0.42, 3)[i % 3]),
            ):
                struct.pack_into("<f", data, offset + field, value)
            for perk, value in ((2, i % 3 == 1), (12, i % 4 == 0)):
                struct.pack_into("<i", data, offset + 0x94 + perk * 4, value)
        pe.write(0x438478, bytes(data))
        ctypes.memmove(check.symbol("player_state_table"), bytes(data), len(data))
        check.dll.combat_world_player(slot, count, kind, distance)
        for addr, value in ((0x452D8C, slot), (0x4428A0, count), (0x4387E8, kind), (0x452E60, 0), (0x452E68, 8)):
            pe.write_u32(addr, value)
        for addr, value in (
            (0x452D40, 1.375),
            (0x452E64, 2.5 if kind else 0),
            (0x4369F0, 235.5 + 100 * slot + distance),
            (0x4369F4, 97.25 - 32 * slot),
            (0x452DBC, 0),
            (0x452E6C, 0),
            (0x452DC8, -1),
            (0x4387B8, 0),
            (0x4387BC, 0),
            (0x452BF8, 0),
            (0x452BFC, 0),
            (0x452DB8, 0),
        ):
            pe.write_f32(addr, value)
        original.reset_draw()
        pe.call(0x4103B0)
        n = check.dll.combat_world_render(1)
        total += original.compare(check, n, ("player", i, kind, distance))
        got = ctypes.string_at(check.symbol("player_state_table"), len(data))
        assert got == pe.read(0x438478, len(data)), (
            "player record",
            i,
            next((k for k, (a, b) in enumerate(zip(got, pe.read(0x438478, len(data)), strict=True)) if a != b), None),
        )
        state = (ctypes.c_float * 24).from_address(check.symbol("combat_world_state"))
        expected = [pe.read_f32(0x452E64), pe.read_i32(0x4387E8)] + [
            pe.read_f32(a)
            for a in (
                0x452DBC,
                0x452E6C,
                0x452DC8,
                0x4387B8,
                0x4387BC,
                0x452BF8,
                0x452BFC,
                0x452DB8,
                0x438504 + slot * 0x188,
            )
        ]
        assert list(state[8:19]) == expected, ("pickup", i, list(state[8:19]), expected)
    return total


def check_effect_draws(check, original):
    pe = original.pe
    original.textures[703] = "part"
    pe.write_u32(0x452C14, 703)
    total = 0

    def record(name, base, size, index, data):
        assert len(data) == size
        pe.write(base + size * index, data)
        ctypes.memmove(check.symbol(name) + size * index, data, size)

    # The PE and both clients see the same raw pools, including the last slot.
    for i in range(36):
        flags = (i * 13) % 32
        kind = i % 8
        time = (265, 39, 59, 0, 100)[i // 8]
        age = (-1, 0, 38, 100, 113, 38)[i % 6]
        check.dll.combat_world_start(0)
        for addr, size in ((0x439F60, 128 * 56), (0x43BB78, 64 * 40), (0x43CBC8, 384 * 44), (0x442AF8, 512 * 128)):
            pe.write(addr, bytes(size))
        for name, size in (
            ("particle_pool", 128 * 56),
            ("secondary_projectile_pool", 64 * 40),
            ("sprite_effect_pool", 384 * 44),
        ):
            ctypes.memset(check.symbol(name), 0, size)
        for j, slot in enumerate((0, 1, 2, 3, 126, 127)):
            data = struct.pack(
                "<BB2x11fB3xi",
                1,
                1,
                240 + j * 13,
                290 - j * 17,
                4,
                5,
                0.75,
                0.23,
                0.39,
                0.617,
                (1, 0.01, -0.2, 0.34, 0.75, 0.91)[j],
                0.27,
                0.32 * j,
                (0, 0, 1, 8, 8, 1)[j],
                0,
            )
            record("particle_pool", 0x439F60, 56, slot, data)
        for j, slot in enumerate((0, 1, 383)):
            record(
                "sprite_effect_pool",
                0x43CBC8,
                44,
                slot,
                struct.pack("<B3x10f", 1, 0.15, 0.41, 0.7, 0.81, 1 + j, 222 + j, 146 - j, 0, 0, 25 + j * 6),
            )
        for j, slot in enumerate((0, 1, 63)):
            record(
                "secondary_projectile_pool",
                0x43BB78,
                40,
                slot,
                struct.pack("<B3x6fifi", 1, 0, 1, 132 + j, 105 - j, 0.35, 0.8, 3 if j != 1 else 2, 0, 0),
            )
        for j, slot in enumerate((0, 1, 511)):
            data = bytearray(128)
            data[0] = 1
            for offset, val in ((20, 16), (24, (98, 194.28, 353)[j]), (28, 105), (40, 825 if j != 2 else 0)):
                struct.pack_into("<f", data, offset, val)
            record("creature_pool", 0x442AF8, 128, slot, bytes(data))
        for slot in range(2):
            data = bytearray(0x188)
            for offset, val in (
                (0x28, 0 if slot and i % 3 == 2 else 55),
                (0x4C, 350.5 + (24 if i % 5 == 0 else slot * 3)),
                (0x50, 210.25),
            ):
                struct.pack_into("<f", data, offset, val)
            record("player_state_table", 0x438478, 0x188, slot, bytes(data))
        for addr, val in ((0x44289E, flags & 1), (0x44289F, int(bool(flags & 2))), (0x452DB4, int(bool(flags & 4)))):
            pe.write_u8(addr, val)
        for addr, val in (
            (0x4428A0, 2 if flags & 16 else 1),
            (0x4387E8, kind),
            (0x452E68, 8),
            (0x452E80, 0),
            (0x452DA0, 0),
        ):
            pe.write_u32(addr, val)
        for addr, val in (
            (0x452D40, 1.375),
            (0x452E94, 0.03125),
            (0x452E5C, 11 if flags & 8 else 10),
            (0x452E64, time / 100),
            (0x452DC8, age / 100),
            (0x4387B8, 97),
            (0x4387BC, 105),
            (0x4369F0, 350.5),
            (0x4369F4, 210.25),
            (0x438800, 166.25),
            (0x438804, 135.75),
        ):
            pe.write_f32(addr, val)
        check.dll.combat_world_effect(flags, kind, time, age)
        original.reset_draw()
        pe.call(0x4110A0)
        n = check.dll.combat_world_render(2)
        total += original.compare(check, n, ("effects", i, flags, kind, time, age))
        state = (ctypes.c_float * 24).from_address(check.symbol("combat_world_state"))
        assert (state[1], state[12], state[19]) == (pe.read_i32(0x452E80), pe.read_f32(0x452DC8), pe.read_i32(0x452DA0))
        assert ctypes.string_at(check.symbol("creature_pool"), 512 * 128) == pe.read(0x442AF8, 512 * 128)
        if age > 100:
            # Submit the four queued scorches to the terrain target on the following frame.
            for a in (0x452E80, 0x452E84, 0x452E88):
                pe.write_u32(a, 0)
            pe.write_u8(0x452D51, 0)
            original.reset_draw()
            pe.call(0x40E830)
            total += original.compare(check, check.dll.combat_world_impacts(), ("scorches", i))
    return total


def check_terrain_draws(check, original):
    pe = original.pe
    original.textures[710] = "ground"
    pe.write_u32(0x452D28, 710)
    total = 0
    for safe in (0, 1):
        for sharp in (0, 1):
            for w, h in ((1024, 1024), (255, 257), (513, 256), (0, 0)):
                check.dll.combat_world_start(0)
                pe.write_f32(0x43CBC0, -27.5)
                pe.write_f32(0x43CBC4, 11.25)
                pe.write_u32(0x42FBD8, w)
                pe.write_u32(0x42FBDC, h)
                pe.write_u8(0x44289D, sharp)
                pe.write_u8(0x452D51, safe)
                original.reset_draw()
                pe.call(0x40F340)
                n = check.dll.combat_world_ground(safe, sharp, w, h)
                total += original.compare(check, n, ("terrain", safe, sharp, w, h))
                fields = (ctypes.c_float * 24).from_address(check.symbol("combat_world_state"))
                assert fields[20] == original.filter == 2
    return total


def check_fx_queue(check, original):
    pe = original.pe
    original.textures.update({711: "blood", 712: "icemold"})
    pe.write_u32(0x43C6AC, 711)
    pe.write_u32(0x452D2C, 701)
    pe.write_u32(0x452D28, 710)
    pe.write_u8(0x44289C, 1)
    args = pe.alloc(24)
    total = 0
    counters = (0x452DA0, 0x452E80, 0x452E88, 0x452E84)
    for mask in range(16):
        for safe in (0, 1):
            for a in counters:
                pe.write_u32(a, 0)
            pe.rand_state = 73
            check.dll.combat_world_start(0)
            count = 70 if mask == 15 else 3
            check.dll.combat_world_queue_seed(mask, count)
            for i in range(count):
                color = (0.25, 0.375, 0.625, 0.75)
                pe.write(args, struct.pack("<6f", 134 + i * 1.25, 241 - i * 0.5, *color))
                if mask & 1:
                    pe.call(0x405C80, 712, args, 14.0 + i, 23.5 + i, 0.125 * i, *color)
                if mask & 2:
                    pe.call(0x40E6B0, args)
                if mask & 4:
                    pe.call(0x40E730, args, args + 8, 0.125 * i, 32.0 + i, i % 2)
                if mask & 8:
                    pe.call(0x40E6F0, args)
            for frame, mode in enumerate((safe, safe, 0)):
                before = [pe.read_i32(a) for a in counters]
                pe.write_u8(0x452D51, mode)
                pe.write_f32(0x43CBC0, -27.5 + frame * 7)
                pe.write_f32(0x43CBC4, 11.25 - frame * 3)
                original.reset_draw()
                pe.call(0x40E830)
                n = check.dll.combat_world_queue(mode, frame)
                total += original.compare(check, n, ("fx queue", mask, mode, frame))
                fields = (ctypes.c_float * 24).from_address(check.symbol("combat_world_state"))
                assert list(fields[:4]) == [pe.read_i32(a) for a in counters]
                assert list(fields[4:6]) == ([0, n] if mode else [n, 0])
                assert original.targets == ([710, 0xFFFFFFFF] if any(before) and not mode else [])
                assert pe.rand_state == ctypes.c_uint32.from_address(check.symbol("freeware_rng_state")).value
    return total
