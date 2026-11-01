"""Drive the original menu callbacks with the clients' foreground input cases."""

import struct


def check_early_menu(pe, edition, lines, labels, samples, keys, slot):
    early = edition == "1.0.2"
    if early:
        frame, state, mode, active, cursor = 0x40C110, 0x41C09C, 0x41C0A0, 0x428800, 0x4220F0
        options, glow, selected, scale = 0x428864, 0x41C099, 0x4287F8, 0x41C080
        setup, setup_end, free, malloc = 0x4106D9, 0x4107DC, 0x410A98, 0x4127E8
        key_slot, main_top, glow_top, last = 0x38, 220, 340, 5
    else:
        frame, state, mode, active, cursor = 0x412FD0, 0x4290D4, 0x4374B0, 0x447774, 0x430288
        options, glow, selected, scale = 0x447808, 0x4374A4, 0x44776C, 0x4290B4
        setup, setup_end, free, malloc = 0x41B516, 0x41B643, 0x41BC48, 0x41DDC0
        key_slot, main_top, glow_top, last = 0x40, 200, 326, 6
        pe.call(0x4011E0)  # Initialize the released defaults, including one player and FPS off.
    key_edges = set()
    slot(key_slot + 4, 1, lambda call: int(call.arg_u32(0) in key_edges))
    slot(key_slot + 12, 1, lambda call: int(click and call.arg_u32(0) == 0))
    # Run the startup block that constructs both label tables, including the original strdup.
    pe.stub(free, 0)
    pe.stub(malloc, lambda call: pe.alloc(call.arg_u32(0)))
    pe.run(setup, setup_end)
    pe.write_u32(state, 1)
    pe.write_u32(mode, 1)
    pe.write_u32(selected, 0)
    pe.write_f32(scale, 1)
    pe.write_u8(glow, 0)
    baseline = pe.snapshot()

    rows = iter(tuple(map(int, line.split()[1:])) for line in lines if line.startswith("earlymenu "))
    for scene, ticks in enumerate((1, 1, 3, 2, 4, 1, 1)):
        pe.restore(baseline)
        pe.write_u8(active, scene == 1)
        pe.write_u8(options, scene in (2, 3, 5))
        for tick in range(ticks):
            keys.clear()
            key_edges.clear()
            x, y = 225, main_top + 5
            click = scene in (1, 2, 6) or (scene == 3 and tick == 0)
            if scene in (0, 5):
                keys.add(0x1C)
                key_edges.add(0x1C)
            if scene == 1:
                y += last * 32
            elif scene == 2:
                offsets = (29, 30, 5) if early else (25, 26, 5)
                x, y = 185, glow_top + offsets[tick]
            elif scene == 3:
                x, y = 185, 217
            elif scene == 4:
                x, y = 10, 100
                key = (0x14, 0x17, 0x19, 0x1F)[tick]  # T, I, P, S with left Control held.
                keys.update((0x1D, key))
                key_edges.add(key)
            elif scene == 5:
                x, y = 185, glow_top + 5
            pe.write(cursor, struct.pack("<2f", x, y))
            samples.clear()
            labels.clear()
            running = pe.call(frame).eax & 0xFF
            expected = (
                scene,
                tick,
                pe.read_u32(state),
                pe.read_u8(options),
                pe.read_u8(active),
                int(running == 0),
                pe.read_u8(glow),
                samples.count(17),
                int(b"Sound volume: default" in labels),
            )
            observed = next(rows)
            assert observed == expected, (edition, observed, expected)
    assert next(rows, None) is None
    print(f"{edition}: 13 original menu frames matched input, state, sound and text")
