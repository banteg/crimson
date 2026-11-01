"""Run complete gameplay callbacks in the two early Windows executables."""

import math
import struct

from freeware_acquisition_cases import mount_level_files
from freeware_arsenal_cases import original


def check_early_frames(exe, edition, lines):
    early = edition == "1.0.2"
    keys = set()
    pe, samples = original(exe, early, keys=keys, buttons=())
    if early:
        frame, state, mode, active, spawn = 0x40C110, 0x41C09C, 0x41C0A0, 0x428800, 0x4287F6
        dt, clock, seconds, timer, scale = 0x428884, 0x428888, 0x428810, 0x42886C, 0x41C080
        camera, cursor, pos, hp, xp, weapon, ammo = 0x424AC0, 0x4220F0, 0x421E9C, 0x421EAC, 0x421EF8, 0x421F8C, 0x421EE8
        pool, count, shot_spawn = 0x4252D0, 0x428868, 0x402B70
        grim, key_slot, texture_slot, ground_start, ground_end = 0x4287EC, 0x38, 0x6C, 0x406020, 0x40629D
    else:
        frame, state, mode, active, spawn = 0x412FD0, 0x4290D4, 0x4374B0, 0x447774, 0x447764
        dt, clock, seconds, timer, scale = 0x447828, 0x447720, 0x447784, 0x447810, 0x4290B4
        camera, cursor, pos, hp, xp, weapon, ammo = 0x433F18, 0x430288, 0x42FFA8, 0x42FFB8, 0x430010, 0x4300AC, 0x42FFFC
        pool, count, shot_spawn = 0x4374F8, 0x44780C, 0x4060D0
        grim, key_slot, texture_slot, ground_start, ground_end = 0x447754, 0x40, 0x88, 0x40B250, 0x40B510
        pe.write_u32(0x4290B8, 640)
        pe.write_u32(0x4290BC, 480)
        pe.write_u32(0x4374B4, 2)
        pe.write_u32(0x4374BC, 0)

    table = pe.read_u32(pe.read_u32(grim))
    ground, labels = [], []

    def slot(offset, arguments, result=0, *, fp=False):
        fn = pe.load_code(b"\xc3")
        pe.stub(fn, result, pop=4 * arguments, returns="st0" if fp else "eax")
        pe.write_u32(table + offset, fn)

    def quad(call):
        if ground_start <= call.return_address < ground_end:
            ground.append((call.arg_f32(0), call.arg_f32(1)))

    def text(call):
        labels.append(pe.read(call.arg_u32(2), 64).split(b"\0", 1)[0])

    # The released Grim interfaces differ in slot positions and use a 24-byte by-value config argument.
    for i, argc in enumerate((1, 1, 0, 0, 0, 1, 4, 3, 4, 5, 4, 8, 3)):
        slot(texture_slot + i * 4, argc, {10: quad, 12: text}.get(i, 0))
    slot(0x14 if early else 0x1C, 7)
    slot(0x20 if early else 0x28, 4)
    slot(0x24 if early else 0x2C, 1)
    slot(key_slot - 8, 0, lambda _: delta, fp=True)
    slot(key_slot - 4, 0, lambda _: 1 / delta, fp=True)
    slot(key_slot + 32, 0, lambda _: dx, fp=True)
    slot(key_slot + 36, 0, lambda _: dy, fp=True)
    if not early:
        slot(8, 1)
        slot(0x74, 1, -1)
        slot(0x78, 1)
    for name in ("_FSOUND_SetFrequency@8", "_FSOUND_SetVolume@8"):
        pe.stub_import(name, 0, pop=8)
    pe.stub_import("_FSOUND_StopSound@4", 0, pop=4)
    # Filename I/O and text entry are supplied at host boundaries. Drawing and simulation run inside the PE.
    pe.stub(0x40BD00 if early else 0x412B00, lambda _: name_key)
    pe.stub(0x410EA3 if early else 0x41BF73, 0)
    if not early:
        mount_level_files(pe, lambda: exe.parent)
    baseline = pe.snapshot()
    rows = iter(line.split()[1:] for line in lines if line.startswith("earlyframe "))
    overlay_rows = iter(line.split()[1:] for line in lines if line.startswith("deathoverlay "))
    total = 0
    for scene in range(10):
        level_test = 5 <= scene <= 8
        escape_during_death = scene == 9
        if early and (scene == 2 or level_test):
            continue
        pe.restore(baseline)
        pe.write_u32(state, 3)
        pe.write_u32(mode, 3 if level_test else 2 if scene in (1, 2) else 1)
        pe.write_u8(active, 1)
        pe.write_u8(spawn, scene in (0, 1, 2))
        pe.write_f32(scale, 1)
        if level_test:
            pe.write_u32(0x44782C, scene - 5)
            pe.write_u32(0x4374A8, 1)
            pe.call(0x411610)
            level = pe.read_u32(0x433F10)
            first, last = struct.unpack("<2I", pe.read(level + 0x48, 8))
            for ptr in range(first, last, 4):
                pe.write_u8(pe.read_u32(ptr) + 4, 0)
            pe.write(camera, bytes(8))
        pe.write(cursor, struct.pack("<2f", 320, 140))
        pe.write(pos, struct.pack("<2f", 200, 180) if scene == 0 else struct.pack("<2f", 512, 512))
        pe.write_f32(hp, -1 if scene == 3 or escape_during_death else 100)
        if not early:
            pe.write_u32(0x4374A8, 2 if scene == 2 else 1)
            pe.write(pos + 328, struct.pack("<2f", 592, 512))
            pe.write_f32(0x447788, -1)  # No bomb in flight.
            if scene == 3:
                for addr in (0x4374A5, 0x4374A4, 0x4374A1):  # Smoke, glow and shadows.
                    pe.write_u8(addr, 1)
        if scene >= 3:
            pe.write_f32(timer, 100)
        if scene == 4 or level_test:
            pe.write_u8(pool, 1)
            if not early:
                pe.write_u8(pool + 1, 1)
                pe.write_f32(pool + 8, -1)  # Breeder timer. The 1.0.2 record has only the disease tick timer.
            pe.write_f32(pool + (8 if early else 20), 16)
            pe.write(pool + (12 if early else 24), struct.pack("<2f", 110, 100))
            pe.write_f32(pool + (28 if early else 40), 5)
            pe.write_f32(pool + (36 if early else 52), 42)
            pe.write(pool + (80 if early else 96), struct.pack("<i" if early else "<d", 121))
            pe.write_u32(count, 1)
            pe.call(shot_spawn, pe.alloc_f32s(100, 100), 1.57079637, 4)
        pe.rand_state = 42
        delta = 0.0625 if scene >= 3 else 0.03125
        early_quality_counter = 0
        frames = 2 if escape_during_death else 34 if scene == 3 else 64 if level_test else 42 if scene == 4 else 12
        for tick in range(frames):
            ground.clear()
            labels.clear()
            keys.clear()
            if escape_during_death and tick == 1:
                keys.add(1)  # DIK_ESCAPE in the common frame tail.
            dx = -800 if tick == 0 else 1000 if tick == 2 else 0
            dy = 700 if tick == 0 else -1000 if tick == 2 else 0
            name_key = 0xA7
            if scene == 3:
                if 26 <= tick <= 28:
                    early_quality_counter = (tick - 25) * 500
                    if not early:
                        pe.write_u32(0x44784C, early_quality_counter)
                name_key = {29: ord("A"), 30: 8, 31: 8, 32: ord("A"), 33: 9}.get(tick, 0xA7)
            samples.clear()
            assert pe.call(frame).eax & 255 == 1
            if scene == 3:
                quality = (
                    (early_quality_counter, 1, 1, 1)
                    if early
                    else (
                        pe.read_u32(0x44784C),
                        pe.read_u8(0x4374A5),
                        pe.read_u8(0x4374A4),
                        pe.read_u8(0x4374A1),
                    )
                )
                expected_overlay = (tick, *quality, samples.count(17))
                assert tuple(map(int, next(overlay_rows))) == expected_overlay, (edition, expected_overlay)
            row = next(rows)
            assert list(map(int, row[:2])) == [scene, tick]
            expected = [pe.read_u32(state), pe.read_u8(active), pe.rand_state]
            expected.extend(
                pe.read_f32(a) for a in (dt, clock, seconds, camera, camera + 4, cursor, cursor + 4, pos, pos + 4, hp)
            )
            expected.extend((pe.read_u32(xp), pe.read_u32(weapon), pe.read_f32(ammo), pe.read_i32(count)))
            expected.extend(
                (
                    pe.read_u8(pool),
                    pe.read_u8(0x422128 if early else 0x4307D0),
                    *ground[0],
                    int(b"Who were you:" in labels),
                ),
            )
            expected.append(int(any(b"Frags:" in label for label in labels)))
            expected.append(pe.read_u32(0x44782C) if not early else 0)
            fields = [
                "state",
                "active",
                "rng",
                "dt",
                "clock",
                "time",
                "camera_x",
                "camera_y",
                "cursor_x",
                "cursor_y",
                "player_x",
                "player_y",
                "health",
                "xp",
                "weapon",
                "ammo",
                "creatures",
                "creature_active",
                "shot_active",
                "ground_x",
                "ground_y",
                "name_prompt",
                "frag_stats",
                "level_number",
            ]
            for field, want, observed in zip(fields, expected, row[2:], strict=True):
                actual = float(observed)
                assert actual == want if isinstance(want, int) else math.isclose(actual, want, abs_tol=0.0001), (
                    edition,
                    scene,
                    tick,
                    field,
                    want,
                    actual,
                )
            total += 1
    assert next(rows, None) is None
    assert next(overlay_rows, None) is None
    print(f"{edition}: {total} complete original frame callbacks matched game state, ground position and RNG")
