"""`terrain_generate` / `terrain_generate_random` vs the port's generators.

A fake Grim interface records the draw calls: each `grim_bind_texture` opens a layer, each
`grim_set_rotation` + `grim_draw_quad_xy` pair is one stamp, read as the native floats at
`config_texture_scale` 1.0 (so `position *= inv_scale` is exact). `crt_rand` is stubbed with the
same MSVC LCG so every draw's return address can be compared with the port's caller tags.
"""

from __future__ import annotations

import random
import struct

from crimson.sim.terrain_generate import terrain_generate, terrain_generate_random
from grim.rand import Crand, RecordingCrand

# Grim vtable byte offsets (analysis/ghidra/derived/grim2d_vtable_map.csv) and their callee-popped bytes.
_GRIM_SLOTS = {
    0x20: 20,  # grim_set_config_var(id, value), the value passed as a 16-byte variant
    0x2C: 16,  # grim_clear_color(r, g, b, a)
    0x30: 4,  # grim_set_render_target(target)
    0xC4: 8,  # grim_bind_texture(handle, stage)
    0xE8: 0,  # grim_begin_batch()
    0xF0: 0,  # grim_end_batch()
    0xFC: 4,  # grim_set_rotation(radians)
    0x100: 16,  # grim_set_uv(u0, v0, u1, v1)
    0x114: 16,  # grim_set_color(r, g, b, a)
    0x120: 12,  # grim_draw_quad_xy(xy, w, h)
}
_TEXTURE_HANDLE_BASE = 0x1000
_QUEST_META_TERRAIN_IDS = 0x10


def _install_grim(oracle, events: list[tuple]) -> None:
    slots = [oracle.load_code(b"\xc3" + b"\x90" * 15)] * 256
    for offset, pop in _GRIM_SLOTS.items():
        slots[offset // 4] = oracle.load_code(b"\xc2" + struct.pack("<H", pop) + b"\x90" * 13)
    oracle.stub(slots[0xC4 // 4], lambda call: events.append(("bind", call.arg_u32(0))), pop=8)
    oracle.stub(slots[0xFC // 4], lambda call: events.append(("rotation", call.arg_f32(0))), pop=4)

    def draw_quad(call) -> None:
        xy = call.arg_u32(0)
        events.append(("quad", oracle.read_f32(xy), oracle.read_f32(xy + 4)))

    oracle.stub(slots[0x120 // 4], draw_quad, pop=12)
    vtable = oracle.alloc(0x400, data=struct.pack("<256I", *slots))
    oracle.write_u32("grim_interface_ptr", oracle.alloc(0x10, data=struct.pack("<I", vtable)))


def _install_crt_rand(oracle, callers: list[int]) -> None:
    def crt_rand(call) -> int:
        state = (oracle.rand_state * 214013 + 2531011) & 0xFFFF_FFFF
        oracle.rand_state = state
        callers.append(call.return_address)
        return (state >> 16) & 0x7FFF

    oracle.stub("crt_rand", crt_rand)


def _layers(events: list[tuple]) -> list[tuple[int, list[tuple[float, float, float]]]]:
    layers: list[tuple[int, list[tuple[float, float, float]]]] = []
    rotation = None
    for event in events:
        match event:
            case ("bind", handle):
                layers.append((handle - _TEXTURE_HANDLE_BASE, []))
            case ("rotation", value):
                rotation = value
            case ("quad", x, y):
                assert rotation is not None
                layers[-1][1].append((rotation, x, y))
    return layers


def test_terrain_generators_match_native(oracle) -> None:
    events: list[tuple] = []
    callers: list[int] = []
    _install_grim(oracle, events)
    _install_crt_rand(oracle, callers)
    oracle.stub("console_printf", None)
    oracle.write_u32("cv_verbose", oracle.alloc(0x20))
    # Fills the quest table, including the three descriptors the unlock rolls hand to `terrain_generate`.
    oracle.call("quest_database_init")
    oracle.write_f32("config_texture_scale", 1.0)
    oracle.write_u8("terrain_texture_failed", 0)
    oracle.write_u32("terrain_texture_width", 1024)
    oracle.write_u32("terrain_texture_height", 1024)
    handles = oracle.resolve("terrain_texture_handles")
    for slot in range(8):
        oracle.write_u32(handles + 4 * slot, _TEXTURE_HANDLE_BASE + slot)
    quest_meta = oracle.alloc(0x40)
    status = oracle.resolve("game_status_blob")

    rng = random.Random(0x417B80)
    cases: list[tuple[int, int | tuple[int, int, int]]] = []
    # Each unlock branch on both sides of its threshold, from seeds whose rolls reach it.
    for unlock_index, slots in (
        (19, (0, 1, 0)),
        (20, (2, 3, 2)),
        (20, (0, 1, 0)),
        (29, (2, 3, 2)),
        (30, (4, 5, 4)),
        (39, (4, 5, 4)),
        (40, (6, 7, 6)),
        (40, (4, 5, 4)),
        (40, (2, 3, 2)),
        (40, (0, 1, 0)),
    ):
        while terrain_generate_random(Crand(seed := rng.getrandbits(32)), unlock_index).terrain_slots != slots:
            pass
        cases.append((seed, unlock_index))
    cases += [(rng.getrandbits(32), rng.randrange(51)) for _ in range(6)]
    cases += [(rng.getrandbits(32), (rng.randrange(8), rng.randrange(8), rng.randrange(8))) for _ in range(6)]

    failures: list[str] = []
    for seed, target in cases:
        port_rng = RecordingCrand(Crand(seed))
        if isinstance(target, tuple):
            oracle.write(quest_meta + _QUEST_META_TERRAIN_IDS, struct.pack("<3i", *target))
            label = f"terrain_generate slots={target} seed=0x{seed:08x}"
            call = ("terrain_generate", quest_meta)
            setup = terrain_generate(port_rng, target)
        else:
            oracle.write(status, struct.pack("<H", target))
            label = f"terrain_generate_random unlock={target} seed=0x{seed:08x}"
            call = ("terrain_generate_random",)
            setup = terrain_generate_random(port_rng, target)
        events.clear()
        callers.clear()
        oracle.rand_state = seed
        oracle.call(*call)

        layers = _layers(events)
        native_slots = tuple(slot for slot, _ in layers)
        port_layers = (setup.layers.base, setup.layers.overlay, setup.layers.detail)
        if native_slots != setup.terrain_slots:
            failures.append(f"{label}: slots native={native_slots} port={setup.terrain_slots}")
        for name, (_, native), port in zip(("base", "overlay", "detail"), layers, port_layers, strict=True):
            if native != [tuple(stamp) for stamp in port]:
                failures.append(f"{label}: {name} stamps differ")
        if callers != [record.caller for record in port_rng.records]:
            failures.append(f"{label}: rng callers differ")
        if oracle.rand_state != port_rng.state:
            failures.append(f"{label}: rand_state native=0x{oracle.rand_state:08x} port=0x{port_rng.state:08x}")

    assert not failures, "\n".join(failures[:40]) + f"\n{len(failures)} mismatches"
