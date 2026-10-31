"""Whole-record input, secret and weapon probes for the original 1.4 player_update."""

import ctypes
import math
import struct


def check_controls(check):
    pe = check.pe
    base = 0x438478
    table = pe.read_u32(pe.read_u32(0x452D94))

    def method(slot, argc, callback):
        addr = pe.load_code(b"\xc3")
        pe.stub(addr, callback, pop=4 * argc)
        pe.write_u32(table + slot, addr)

    def inputs(held, flags, actor):
        def key(call):
            k = call.arg_u32(0) & 255
            return bool(flags & 8) if k == 0x13 else 32 <= k < 42 and bool(held & (1 << (k - 32)))

        method(0x40, 1, key)
        method(
            0x44,
            1,
            lambda call: (
                ((call.arg_u32(0) & 255) == 36 + actor * 5 and bool(flags & 1))
                or ((call.arg_u32(0) & 255) == 36 + (1 - actor) * 5 and bool(flags & 128))
            ),
        )
        method(0x48, 1, lambda call: bool(flags & (6 if call.arg_u32(0) == 0 else 32)))
        method(0x4C, 1, bool(flags & 4))
        method(0x68, 0, 100 * (bool(held & 8) - bool(held & 4)))
        method(0x6C, 0, 100 * (bool(held & 2) - bool(held & 1)))
        method(0x74, 1, 27000 if flags & 64 else 9000)
        method(0x78, 1, bool(flags & 16))

    scenarios = [
        (move, aim, actor, case)
        for move in (0, 1, 2)
        for aim in range(4)
        for actor in (0, 1)
        for case in ("opposed", "alternate", "neutral", "shot", "snap", "reload", "edge")
    ]
    scenarios += [(0, 0, 0, case) for case in ("rainbow", "bubble", "berserk", "target", "dead", "console", "slow")]
    for move, aim, actor, case in scenarios:
        check.reset(731)
        # Select player 2 in co-op, or exercise its alternate movement/edge bindings in solo.
        count = 1 + actor
        flags = {
            "opposed": 128,
            "alternate": 128,
            "neutral": 0,
            "shot": 18,
            "snap": 1,
            "reload": 4,
            "edge": 32,
            "rainbow": 2,
            "bubble": 256,
            "berserk": 512,
            "target": 512,
            "dead": 2,
            "console": 2048,
            "slow": 1024,
        }[case]
        held = {"opposed": 15, "alternate": 32 | 128, "shot": 16, "snap": 6, "edge": 5}.get(case, 0)
        if actor and case in ("opposed", "shot", "snap"):
            held |= held << 5
        if case == "opposed":
            flags |= 64
        dt = 0.03125
        pe.write_u32(0x4428A8, 2)  # combat_reset starts Survival
        if case in ("rainbow", "bubble"):
            check.dll.combat_arm(18)
            pe.write_u32(0x4428A8, 1)
        for va, value in (
            (0x452D8C, actor),
            (0x4428A0, count),
            (0x4428AC + 4 * actor, (2, 1, 3)[move]),
            (0x4428B4 + 4 * actor, aim),
            (0x452DDC, 3),
            (0x452DEC, 4),
            (0x452E14, 11),
            (0x452DE4, 14),
            (0x452E24, 22),
            (0x452DF8, 5),
            (0x452D80, 7),
            (0x4428C0, 18),
            (0x4428CC, 9000),
            (0x4428D0, 27000),
        ):
            pe.write_u32(va, value)
        for va, value in (
            (0x452E94, dt),
            (0x42FB8C, 0.73),
            (0x438800, 310),
            (0x438804, 169),
            (0x43CBC0, -2),
            (0x43CBC4, -8),
            (0x4387C0, 512),
            (0x4387C4, 512),
            (0x452DC4, 120 if flags & 256 else 7),
            (0x452E5C, 11 if flags & 512 else 0),
            (0x452E6C, int(bool(flags & 1024))),
        ):
            pe.write_f32(va, value)
        pe.write_u8(0x436598, bool(flags & 2048))
        for va, name in (
            (0x452D59, "freeware_secret_weapon_unlocked"),
            (0x452D4D, "freeware_rainbow_armed"),
            (0x4428F4, "freeware_rainbow_enabled"),
        ):
            pe.write_u8(va, 0)
            ctypes.c_ubyte.from_address(check.symbol(name)).value = 0

        inputs(held, flags, actor)
        for i in range(2):
            record = bytearray([0x35] * 0x188)
            for off, value in (
                (0x18, 2 if case == "edge" else 512),
                (0x1C, 1009 if case == "edge" else 512),
                (0x28, 0 if case == "dead" else 3 if case == "rainbow" else 100),
                (0x2C, 0.9),
                (0x34, 48),
                (0x4C, 600),
                (0x50, 570),
                (0x58, 2),
                (0x68, 1.98),
                (0x6C, 1),
                (0x70, 0.06 if case == "reload" else 0),
                (0x7C, 14 if case == "neutral" else 13.98),
                (0x8C, 0),
                (0x90, 1),
                (0x154, 0.87),
                (0x164, 10),
                (0x168, 1.1),
                (0x16C, -1.98),
                (0x170, 8.1),
                (0x178, 0),
            ):
                struct.pack_into("<f", record, off, value)
            record[0x94:0x154] = bytes(192)
            for perk in (4, 11, 14, 22):
                struct.pack_into("<i", record, 0x94 + 4 * perk, 1)
            if case == "snap":
                struct.pack_into("<i", record, 0x94 + 3 * 4, 1)
            struct.pack_into("<i", record, 0x80, 0 if case == "bubble" else 7)
            struct.pack_into("<i", record, 0x15C, 13 if case == "opposed" else 1)
            record[0x17C:0x181] = bytes(range(32 + i * 5, 37 + i * 5))
            pe.write(base + i * 392, bytes(record))
            ctypes.memmove(check.symbol("player_state_table") + i * 392, bytes(record), 392)
        if case == "target":
            # The first MSVCRT draw at this seed selects this exact slot.
            slot = (((731 * 214013 + 2531011) >> 16) & 32767) % 512
            enemy = bytearray(128)
            enemy[0] = 1
            struct.pack_into("<ff", enemy, 24, 650, 555)
            pe.write(0x442AF8 + 128 * slot, bytes(enemy))
            ctypes.memmove(check.symbol("creature_pool") + 128 * slot, bytes(enemy), 128)
        pe.call(0x4126E0)
        check.dll.combat_controls(actor, count, move, aim, held, flags, dt)
        label = move, aim, actor, case
        # Compare both entire records, including unchanged padding, perk slots and the inactive actor.
        floats = {
            0x18,
            0x1C,
            0x20,
            0x24,
            0x2C,
            0x4C,
            0x50,
            0x68,
            0x6C,
            0x70,
            0x7C,
            0x8C,
            0x90,
            0x154,
            0x164,
            0x168,
            0x16C,
            0x170,
        }
        for i in range(2):
            orig = pe.read(base + 392 * i, 392)
            port = ctypes.string_at(check.symbol("player_state_table") + 392 * i, 392)
            for off in range(0, 392, 4):
                a, b = orig[off : off + 4], port[off : off + 4]
                if off in floats:
                    a, b = struct.unpack("<f", a)[0], struct.unpack("<f", b)[0]
                    assert math.isclose(a, b, abs_tol=0.001), (label, i, hex(off), a, b)
                else:
                    assert a == b, (label, i, hex(off), a, b)
        assert pe.rand_state == ctypes.c_uint.from_address(check.symbol("freeware_rng_state")).value, label
        assert pe.read_u8(0x452D7C) == ctypes.c_ubyte.from_address(check.symbol("freeware_player_moved")).value, label
        assert pe.read_i32(0x452D80) == check.dll_globals("freeware_first_kill_xp").value, label
        for va, name in ((0x42FB8C, "time_scale_factor"), (0x438800, "freeware_aim_screen")):
            assert math.isclose(
                pe.read_f32(va),
                ctypes.c_float.from_address(check.symbol(name)).value,
                abs_tol=0.001,
            ), label
        for va, name in (
            (0x452D59, "freeware_secret_weapon_unlocked"),
            (0x452D4D, "freeware_rainbow_armed"),
            (0x4428F4, "freeware_rainbow_enabled"),
        ):
            assert pe.read_u8(va) == ctypes.c_ubyte.from_address(check.symbol(name)).value, (label, name)
        assert math.isclose(
            pe.read_f32(0x438804),
            ctypes.c_float.from_address(check.symbol("freeware_aim_screen") + 4).value,
            abs_tol=0.001,
        ), label
        check.frames += 1
