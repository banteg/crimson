"""Drive the original menu callbacks with the clients' foreground input cases."""

import struct

from freeware_arsenal_cases import floats


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

    def key_pressed(call):
        key = call.arg_u32(0)
        if key in key_edges:
            key_edges.remove(key)
            return 1
        return 0

    def mouse_pressed(call):
        nonlocal click
        if click and call.arg_u32(0) == 0:
            click = False
            return 1
        return 0

    slot(key_slot + 4, 1, key_pressed)
    slot(key_slot + 12, 1, mouse_pressed)
    # Run the startup block that constructs both label tables, including the original strdup.
    pe.stub(free, 0)
    pe.stub(malloc, lambda call: pe.alloc(call.arg_u32(0)))
    pe.run(setup, setup_end)
    pe.write_u32(state, 1)
    pe.write_u32(mode, 1)
    pe.write_u32(selected, 0)
    pe.write_f32(scale, 1)
    pe.write_u8(glow, 0)
    draws = []
    sprites = []
    fades = iter(line.split()[1:] for line in lines if line.startswith("menufade102 "))
    sprite_rows = iter(line.split("\t") for line in lines if line.startswith("menusprite102 "))
    draw_rows = {}
    for line in lines:
        if line.startswith("menurow102 "):
            frame_id, text, coords = line.split("\t")
            _, scene, tick = frame_id.split()
            draw_rows.setdefault((int(scene), int(tick)), []).append((text, list(map(float, coords.split()))))
    if early:
        # Align the portable Game's starting options with the original's in-memory configuration.
        pe.write_u32(0x41C094, 2)  # Static movement.
        pe.write_u8(0x41C098, 1)  # Shadows enabled.
        pe.write_u8(0x4287F5, 0)  # Smooth background.
        pe.write_u8(0x4287F7, 0)  # FPS disabled.
        pe.write_u8(0x4287F4, 0)  # Shell marks disabled.
        color = [1.0] * 4
        font_scale = 1.0
        texture = ""
        rotation = 0.0
        blend = {0xD: 5, 0xE: 6, 0xF: 2}

        def lookup(call):
            nonlocal texture
            texture = pe.read(call.arg_u32(0), 64).split(b"\0", 1)[0].decode("ascii")
            return 0

        def rotate(call):
            nonlocal rotation
            rotation = call.arg_f32(0)

        def quad(call):
            if call.return_address in (0x40C6B1, 0x40CBA0, 0x40CC49, 0x40CD2F):
                position = [call.arg_f32(i) for i in range(4)]
                sprites.append((texture, [*position, rotation, *color, blend[0xF], blend[0xD], blend[0xE]]))

        slot(0x6C, 1, lookup)
        slot(0x80, 1, rotate)
        slot(0x94, 4, quad)

        def set_color(call):
            color[:] = [call.arg_f32(i) for i in range(4)]

        def configure(call):
            nonlocal font_scale
            if call.arg_u32(0) in blend:
                blend[call.arg_u32(0)] = call.arg_u32(1)
            if call.arg_u32(0) == 0x11:
                font_scale = call.arg_f32(2)

        def draw_text(call):
            label = pe.read(call.arg_u32(2), 64).split(b"\0", 1)[0]
            labels.append(label)
            if call.return_address in (0x40C912, 0x40CA52):
                draws.append((label.decode("ascii"), [call.arg_f32(0), call.arg_f32(1), font_scale, *color]))

        slot(0x8C, 4, set_color)
        slot(0x14, 7, configure)
        slot(0x9C, 3, draw_text)
    baseline = pe.snapshot()

    rows = iter(tuple(map(int, line.split()[1:])) for line in lines if line.startswith("earlymenu "))
    scenarios = (1, 1, 3, 2, 4, 1, 1)
    if early:
        # Done by click, Enter, or both; paused mode selection; Escape; overlay entry; active-run title.
        scenarios += (1, 1, 1, 1, 1, 2, 2, 1)
    for scene, ticks in enumerate(scenarios):
        pe.restore(baseline)
        pe.write_u8(active, scene in (1, 9, 14))
        pe.write_u8(options, scene in (2, 3, 5, 7, 8, 10, 11))
        if early:
            pe.write_f32(0x428888, 2.5)
            pe.write_f32(0x4287E0, 1.25 if scene % 2 else 2.25)
            pe.write_u8(0x41C088, scene == 0)
        for tick in range(ticks):
            keys.clear()
            key_edges.clear()
            x, y = 225, main_top + 5
            click = scene in (1, 2, 6, 7, 9, 11) or (scene in (3, 12, 13) and tick == 0)
            if scene in (0, 5, 8, 11):
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
            elif scene in (7, 8, 11):
                x, y = 185, 180 + 8 * 32 + 5
            elif scene == 9:
                y += 32
            elif scene == 10:
                keys.add(1)
                key_edges.add(1)
            elif scene in (12, 13):
                y += (2 if scene == 12 else 3) * 32
            pe.write(cursor, struct.pack("<2f", x, y))
            draws.clear()
            sprites.clear()
            samples.clear()
            labels.clear()
            running = pe.call(frame).eax & 0xFF
            observed_draws = draw_rows.pop((scene, tick), [])
            assert len(observed_draws) == len(draws), (edition, scene, tick, observed_draws, draws)
            for (label, values), (actual_label, actual_values) in zip(draws, observed_draws, strict=True):
                assert actual_label == label, (edition, scene, tick, actual_label, label)
                floats(actual_values, values, (edition, scene, tick, label))
            if scene in (12, 13):
                menu_scene, menu_tick, alpha = next(fades)
                assert (int(menu_scene), int(menu_tick)) == (scene, tick)
                floats([float(alpha)], [pe.read_f32(0x41C084)], (edition, scene, tick, "overlay fade"))
            for texture_name, values in sprites:
                tag, actual_texture, actual_values = next(sprite_rows)
                assert (tag, actual_texture) == (f"menusprite102 {scene} {tick}", texture_name), (
                    scene, tick, actual_texture, texture_name,
                )
                floats(list(map(float, actual_values.split())), values, (scene, tick, texture_name))
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
                int(pe.read_u32(mode) == 2),
                int(b"Highscores:" in labels),
                int(b"Project Crimsonland" in labels),
            )
            observed = next(rows)
            assert observed == expected, (edition, observed, expected)
    assert next(rows, None) is None
    assert next(sprite_rows, None) is None
    assert next(fades, None) is None
    assert not draw_rows
    print(f"{edition}: {sum(scenarios)} original menu frames matched input, state, sound and text")
