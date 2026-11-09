"""Compare the in-frame 1.0.2 HUD to the portable renderer, including draw order and gameplay writes."""

from freeware_arsenal_cases import floats, original


def check_early_hud(exe, lines):
    pe, _ = original(exe, True, buttons=())
    vtable = pe.read_u32(pe.read_u32(0x4287EC))
    textures = ["bar", "bullet_i", "bullet", "ui_text"]
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
        for kind, label, expected in calls:
            tag, actual_label, values = next(rows)
            assert (tag, actual_label) == (f"hud102 {sample} {kind}", label)
            floats([float(x) for x in values.split()], expected, (tag, label))
    assert next(rows, None) is None
    print(f"1.0.2: {total} original HUD draws and 12 final gameplay states matched")
