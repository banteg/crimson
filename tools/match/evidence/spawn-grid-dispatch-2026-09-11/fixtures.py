"""Deterministic spawn cases and compiler-checked observation layout."""

import itertools
import struct
from dataclasses import replace

from execute import match

FIELDS = {
    "active": (0, "B"),
    "phase_seed": (4, "i"),
    "pos_x": (20, "f"),
    "pos_y": (24, "f"),
    "health": (36, "f"),
    "max_health": (40, "f"),
    "heading": (44, "f"),
    "type_id": (108, "i"),
    "link_index": (120, "i"),
    "target_offset_x": (124, "f"),
    "target_offset_y": (128, "f"),
}


def check_layout(config, out):
    directory = out / "layout"
    directory.mkdir(exist_ok=True)
    layout = {
        "sizeof(creature_t)": 152,
        "sizeof(creature_spawn_slot_t)": 24,
        "sizeof(creature_pool) / sizeof(creature_pool[0])": 385,
        "sizeof(creature_spawn_slot_table) / sizeof(creature_spawn_slot_table[0])": 32,
        "sizeof(config_hardcore)": 1,
        "sizeof(demo_mode_active)": 1,
        "offsetof(cvar_float_t, value)": 12,
    }
    for name, (offset, _) in FIELDS.items():
        layout[f"offsetof(creature_t, {name})"] = offset
    for offset, name in enumerate(("owner", "count", "limit", "interval_s", "timer_s", "template_id")):
        layout[f"offsetof(creature_spawn_slot_t, {name})"] = 4 * offset
    source = '#include "crimsonland_gameplay.h"\n#include <stddef.h>\nextern "C" {\n'
    source += "unsigned int execution_offsets[] = {" + ", ".join(layout) + "};\n}\n"
    (directory / "scratch.cpp").write_text(source)
    path = match.compile_scratch(replace(config, directory=directory))
    obj = match.parse_coff_object(path.read_bytes())
    symbol = next(row for row in obj.symbols if row.name == "_execution_offsets")
    raw = obj.sections[symbol.section_number - 1].data[symbol.value : symbol.value + 4 * len(layout)]
    actual = struct.unpack("<" + "I" * len(layout), raw)
    assert list(actual) == list(layout.values()), dict(zip(layout, actual, strict=True))
    return layout


def creature(state, index):
    return {
        name: struct.unpack_from("<" + fmt, state, index * 152 + offset)[0] for name, (offset, fmt) in FIELDS.items()
    }


def scenarios():
    cases = []
    for template, cw, hardcore, retry, rng in itertools.product(
        range(68),
        (0x7F, 0x37F),
        (0, 1),
        (0, 3),
        ("lcg", "linear"),
    ):
        cases.append(
            {"template": template, "fpcw": cw, "hardcore": hardcore, "retry": retry, "seed": template + 1, "rng": rng},
        )
    for template, heading, occupied, demo in itertools.product(range(68), (0.0, 0.75), (3, 17), (0, 1)):
        cases.append(
            {
                "template": template,
                "heading": heading,
                "occupied": occupied,
                "demo": demo,
                "seed": 0xBEEF,
                "stack_fill": 0x5A,
                "slots_occupied": 31,
            },
        )
    for template, heading, occupied, position, cw in itertools.product(
        range(0x14, 0x19),
        (0.0, 0.75, -100.0),
        (0, 356),
        ((100.0, 200.0), (-0.25, 1024.25), (0.0, 0.0)),
        (0x7F, 0x37F),
    ):
        cases.append(
            {
                "template": template,
                "heading": heading,
                "occupied": occupied,
                "position": position,
                "fpcw": cw,
                "seed": 0xBEEF,
                "stack_fill": 0,
            },
        )
    for template, cw in itertools.product((0, 7, 8, 9, 10, 11, 12, 13, 16, 31, 65), (0x7F, 0x37F)):
        cases.append({"template": template, "occupied": 383, "slots_occupied": 32, "fpcw": cw, "demo": 1})
    # Exercise every retry jump-table destination and its interval clamp. The
    # static reference audit still reports differing local table offsets.
    for template, retry, cw in itertools.product(range(68), (-1, 1, 2, 4, 5, 8, 9, 10), (0x7F, 0x37F)):
        cases.append({"template": template, "retry": retry, "fpcw": cw, "seed": 0xBEEF})
    # The real allocator returns the declared overflow slot when all 384
    # regular entries are active; keep that storage visible in the comparison.
    for template, cw in itertools.product((0x14, 0x18, 0x1f), (0x7F, 0x37F)):
        cases.append({"template": template, "occupied": 384, "fpcw": cw, "seed": 0xBEEF})
    for index, case in enumerate(cases):
        case["name"] = f"spawn-{index}-template-{case['template']:02x}"
    return cases
