"""Compare 1.0.2 frame draws and state changes against the original executable."""

from freeware_arsenal_cases import floats, original


def draw_oracle(exe, textures):
    pe, _ = original(exe, True, buttons=())
    vtable = pe.read_u32(pe.read_u32(0x4287EC))
    state = {}
    calls = []

    def name(address):
        return pe.read(address, 96).split(b"\0", 1)[0].decode("ascii")

    def slot(offset, argc, handler):
        thunk = pe.load_code(b"\xc3")
        pe.stub(thunk, handler, pop=4 * argc)
        pe.write_u32(vtable + offset, thunk)

    def config(c):
        if c.arg_u32(0) == 0xF:
            state["filter"] = c.arg_u32(1)
        elif c.arg_u32(0) == 0x11:
            state["scale"] = c.arg_f32(2)

    def floats_slot(key, count):
        def setter(c):
            state[key] = [c.arg_f32(i) for i in range(count)]
        return setter

    def bind(c):
        state["texture"] = textures[c.arg_u32(0)]

    def quad(c):
        values = [c.arg_f32(i) for i in range(4)] + state["angle"] + state["uv"]
        calls.append(("quad", state["texture"], values + [state["filter"]] + state["color"]))

    def text(c):
        values = [c.arg_f32(0), c.arg_f32(1), state["scale"]] + state["color"]
        calls.append(("text", name(c.arg_u32(2)), values))

    slot(0x6C, 1, lambda c: textures.index(name(c.arg_u32(0))))
    slot(0x70, 1, bind)
    slot(0x74, 0, 0)
    slot(0x7C, 0, 0)
    slot(0x80, 1, floats_slot("angle", 1))
    slot(0x84, 4, floats_slot("uv", 4))
    slot(0x8C, 4, floats_slot("color", 4))
    slot(0x94, 4, quad)
    slot(0x9C, 3, text)
    slot(0x14, 7, config)
    return pe, state, calls


def compare_draws(rows, tag, sample, calls):
    for kind, label, expected in calls:
        actual_tag, actual_label, values = next(rows)
        assert (actual_tag, actual_label) == (f"{tag} {sample} {kind}", label)
        floats([float(x) for x in values.split()], expected, (actual_tag, label))


def check_early_hud(exe, lines):
    textures = ["bar", "bullet_i", "bullet", "ui_text"]
    pe, state, calls = draw_oracle(exe, textures)
    pe.write_u32(0x424EC8, textures.index("bullet_i"))
    baseline = pe.snapshot()
    rows = iter(line.split("\t") for line in lines if line.startswith("hud102 "))
    total = 0
    for sample in range(12):
        pe.restore(baseline)
        calls.clear()
        state.update(texture="bullet", filter=2, scale=1, angle=[0], uv=[0, 0, 1, 1], color=[1] * 4)
        health = 0 if sample == 5 else -3 if sample == 9 else 78 + sample
        for address, value in (
            (0x41C09C, 3), (0x41C0A0, 1 + sample % 2), (0x4287E8, 0), (0x421EF8, 1234 + sample),
            (0x428860, sample % 3), (0x421F8C, sample + 1),
        ):
            pe.write_u32(address, value)
        for address, value in (
            (0x421EAC, health), (0x428810, 17.625), (0x428884, .125), (0x428888, 51.75),
            (0x421EE8, 3 + sample % 4), (0x421F94, 11 + sample % 3),
        ):
            pe.write_f32(address, value)
        # Starting at the first HUD draw, run through the pending-perk hit test with no input.
        pe.run(0x40DAB9, 0x40E4AC)
        total += len(calls)
        calls.append(("state", "-", [pe.read_u32(0x41C09C), pe.read_f32(0x428810),
                                     pe.read_f32(0x421EE8), pe.read_f32(0x421EAC)]))
        compare_draws(rows, "hud102", sample, calls)
    assert next(rows, None) is None
    print(f"1.0.2: {total} original HUD draws and 12 final gameplay states matched")


def check_early_name(exe, lines):
    pe, state, calls = draw_oracle(exe, ["reaper", "part", "aim32"])
    rows = iter(line.split("\t") for line in lines if line.startswith("name102 "))
    saves = []

    def save(c):
        assert (c.arg_u32(1), c.arg_u32(2)) == (36, 1)
        record = c.arg_u32(0)
        name = pe.read(record, 32).split(b"\0", 1)[0].decode("ascii")
        saves.append(("save", name, [pe.read_u32(record + 32)]))
        return 1

    # Capture the original score writer's complete record in memory.
    pe.stub(0x410EA3, 1)  # fopen
    pe.stub(0x410DF7, 0)  # fseek
    pe.stub(0x410CED, save)
    pe.stub(0x410C97, 0)  # fclose
    pe.stub(0x40F880, 1)  # Begin after the separately covered overlay backdrop.
    baseline = pe.snapshot()
    total = 0
    for mode in (1, 2):
        pe.restore(baseline)
        saves.clear()
        pe.write_f32(0x4287E0, 2)
        pe.write_u8(0x428800, 1)
        pe.write_u32(0x41C09C, 6)
        pe.write_u32(0x41C0A0, mode)
        pe.write(0x422100, b"10tons\0" if mode == 1 else b"Arsenal\0")
        pe.write_u32(0x421EF8, 1234)
        pe.write_f32(0x428810, 42.625)
        pe.write_f32(0x4220F0, 121.5)
        pe.write_f32(0x4220F4, 267.25)
        for step, key in enumerate((0xA7, ord("A"), 8, 8, ord("X"), 9)):
            pe.stub(0x40BD00, key)  # Keyboard event consumed by this frame.
            pe.write_f32(0x428888, 2 + step * .31)
            state.update(filter=3, scale=1, angle=[0], uv=[0, 0, 1, 1], color=[1] * 4)
            calls.clear()
            pe.run(0x40E4FA, 0x40EC65)
            total += len(calls)
            name = pe.read(0x422100, 32).split(b"\0", 1)[0].decode("ascii")
            final = [pe.read_u32(0x41C09C), pe.read_u32(0x428898), pe.read_u8(0x428800),
                     pe.read_f32(0x4287E0), pe.read_f32(0x4287F0), len(saves)]
            calls.append(("state", name, final))
            calls.extend(saves)
            compare_draws(rows, "name102", (mode - 1) * 6 + step, calls)
        assert len(saves) == 1
    assert next(rows, None) is None
    print(f"1.0.2: {total} original name-entry draws, 12 final states and 2 saved scores matched")


def check_name_edit_130(exe, lines):
    pe, _ = original(exe, False)
    rows = iter(row.split("\t") for row in lines if row.startswith("name130 "))
    address = 0x430798
    saved = []

    def name():
        return pe.read(address, 32).split(b"\0", 1)[0].decode("ascii")

    # The score writer has its own oracle. Capture the name at its real call site.
    pe.stub(0x404510, lambda c: saved.append(name()) or 1)
    pe.stub(0x4046C0, 1)
    pe.write(address, b"Prior\0")
    for round_id, keys in enumerate(((9,), (0xA7, ord("A"), 8, ord("Z"), 9))):
        pe.write_u32(0x44783C, 4)
        pe.write_u8(0x447774, 1)
        pe.write_u8(0x447831, 0)
        pe.write_u8(0x4290DC, 0)
        pe.write_u32(0x4290D4, 8)
        for key in keys:
            pe.run(0x4178D8, 0x4178F2)  # Active-run entry resets only the cursor.
            pe.stub(0x412B00, key)
            pe.run(0x417E01, 0x417EC8)  # Consume one name key, including save and table reload on Tab.
            head, actual, fields, last = next(rows)
            assert head == f"name130 {round_id} {key}"
            expected = [pe.read_u32(0x44783C), pe.read_u8(0x447774), pe.read_u8(0x447831),
                        pe.read_u8(0x4290DC), len(saved)]
            assert (actual, list(map(int, fields.split())), last) == (name(), expected, saved[-1])
    assert next(rows, None) is None
    print("1.3.0: retained and edited names matched both original score submissions")
