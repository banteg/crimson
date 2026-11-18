"""Replay consecutive keyboard and gamepad inputs through each early player_update."""

from freeware_arsenal_cases import floats, original


def check_player_motion(exe, edition, lines):
    early = edition == "1.0.2"
    keys = set()
    mouse = set()
    pe, _ = original(exe, early, keys, mouse)
    if early:
        update, dt, pos, motion, heading = 0x408040, 0x428884, 0x421E9C, 0x421EA4, 0x421EB0
        speed, walk, spread, aim = 0x421EE4, 0x421EF4, 0x421F84, 0x421ECC
        cursor, camera, cooldown = 0x4220F0, 0x424AC0, 0x421F00
        primary, secondary = (0x11, 0x1F, 0x1E, 0x20), (0xC8, 0xD0, 0xCB, 0xCD)
    else:
        update, dt, pos, motion, heading = 0x40E430, 0x447828, 0x42FFA8, 0x42FFB0, 0x42FFBC
        speed, walk, spread, aim = 0x42FFF8, 0x43000C, 0x4300A4, 0x42FFDC
        cursor, camera, cooldown = 0x430288, 0x433F18, 0x43001C
        primary, secondary = range(32, 37), range(37, 42)
        pe.write(0x4300CC, bytes(primary))
        pe.write(0x430214, bytes(secondary))
        table = pe.read_u32(pe.read_u32(0x447754))
        # Feed the original Grim input boundary, leaving its pad calibration and POV tests intact.
        for offset, read, pop in (
            (0x44, lambda c: c.arg_u32(0) & 255 == (37 if actor else 32) + 4 and tick == 4, 4),
            (0x68, lambda _: 100 * (bool(mask & 8) - bool(mask & 4)), 0),
            (0x6C, lambda _: 100 * (bool(mask & 2) - bool(mask & 1)), 0),
            (0x74, lambda _: (27000, -1, 9000)[tick % 3], 4),
            (0x78, lambda _: int(tick == 9), 4),
        ):
            getter = pe.load_code(b"\xc3")
            pe.stub(getter, read, pop=pop)
            pe.write_u32(table + offset, getter)
        pe.write_u32(0x4374C8, 10)
        pe.write_u32(0x4374D4, 9000)
        pe.write_u32(0x4374D8, 27000)
    pe.write_f32(dt, 0.0625)
    pe.write_f32(camera, 19)
    pe.write_f32(camera + 4, -13)
    pe.write_f32(0x41C080 if early else 0x4290B4, 1)
    pe.write_u32(0x41C0A0 if early else 0x4374B0, 1)
    state = pe.snapshot()
    count = 0
    for line in lines:
        if not line.startswith("motion "):
            continue
        _, move, mode, who, frame, flags, *values = line.split()
        movement, aiming, actor, tick, mask = map(int, (move, mode, who, frame, flags))
        offset = actor * 328
        if tick == 0:
            pe.restore(state)
            pe.rand_state = 123
            if early:
                pe.write_u32(0x41C094, (2, 1)[movement])
            else:
                pe.write_u32(0x44774C, actor)
                pe.write_u32(0x4374A8, actor + 1)
                pe.write_u32(0x4374B4 + actor * 4, (2, 1, 3)[movement])
                pe.write_u32(0x4374BC + actor * 4, {0: 0, 2: 1, 3: 2}[aiming])
                pe.write_f32(0x4300BC + offset, -0.75)
                pe.write_f32(0x4300C0 + offset, 1.25)
            for addr, val in [
                (pos, 26),
                (pos + 4, 26),
                (cooldown, 0.375),
                (spread, 1.875),
                (0x421F98 if early else 0x4300B8, 1.25),
                (heading, 0.25),
                (aim, 66),
                (aim + 4, 62),
                (walk, 13.875),
            ]:
                pe.write_f32(addr + offset, val)
        pe.write_f32(cursor, 70 + tick * 5)
        pe.write_f32(cursor + 4, 54 - tick * 2)
        row = secondary if actor or tick == 9 else primary
        keys.clear()
        keys.update(k for bit, k in enumerate(row) if mask & (1 << bit))
        if early and tick in (4, 5):
            keys.add(0x1D)
        if tick == 11:
            keys.add(0x1C if early else row[4])
        mouse.clear()
        if tick == 7:
            mouse.add(0)
        pe.call(0x402CA0 if early else 0x406260)
        flash = (0x421F98 if early else 0x4300B8) + offset
        flash_before_player = pe.read_f32(flash)
        pe.call(update)
        data = list(map(float, values[:-1]))
        fields = (pos, pos + 4, motion, motion + 4, heading, speed, walk, spread, aim, aim + 4)
        expected = [pe.read_f32(addr + offset) for addr in fields]
        if early:
            # This build has no stored aim heading or turn-speed accumulator.
            del data[10:12]
        else:
            expected.extend(pe.read_f32(addr + offset) for addr in (0x4300BC, 0x4300C0))
        expected.extend((pe.read_f32(cursor), pe.read_f32(cursor + 4)))
        expected.extend(
            (
                flash_before_player,
                pe.read_f32(flash),
                pe.read_f32((0x421EE8 if early else 0x42FFFC) + offset),
                pe.read_f32(cooldown + offset),
                pe.read_f32(0x42212C if early else 0x4307D4),
            ),
        )
        case = edition, movement, aiming, actor, tick
        floats(expected, data, case)
        assert pe.rand_state == int(values[-1]), case
        count += 1
    assert count == (24 if early else 72)
    print(f"{edition}: {count} consecutive movement and aim frames matched")
