"""Recreate recovered globals without assuming 32-bit host pointers."""

import json
import re


def data_source(root, out):
    d = json.loads((root / "tools/native/data_definitions/crimsonland.exe.json").read_text())
    entries = list(d["entries"])
    for g in d["groups"]:
        for m in g["members"]:
            entries.append(
                {
                    "address": m[0],
                    "name": m[1],
                    "size": g["size"],
                    "initializer_hex": m[2] if len(m) > 2 else g.get("initializer_hex", ""),
                },
            )
    # C++ constructors own these pointer-bearing tables at each platform's stride.
    owned = {"quest_meta_table", "perk_meta_table", "bonus_meta_table"}
    ownranges = [
        (int(e["address"], 16), int(e["address"], 16) + e["size"], e["name"]) for e in entries if e["name"] in owned
    ]
    interiors = [
        (e, a, name)
        for e in entries
        for a, b, name in ownranges
        if a <= int(e["address"], 16) < b and e["name"] != name
    ]
    entries = [e for e in entries if not any(a <= int(e["address"], 16) < b for a, b, _ in ownranges)]
    # Recovered owner headers intentionally access a contiguous aggregate through its first symbol.
    ranges = [(0x486FA8, 0x487150), (0x48F530, 0x48F588)]
    # Spans from the first symbol through the end of the last keep native overreads on the original bytes:
    # `fx_queue_render` reads the corpse frame of type 7 (ping-pong strips) from `creature_type_count`.
    extents = {e["name"]: (int(e["address"], 16), int(e["address"], 16) + e["size"]) for e in entries}
    for first, last in [
        ("ui_mouse_x", "ui_mouse_y"),
        ("render_scratch_f0", "render_scratch_f1"),
        ("render_scratch_f2", "render_scratch_f3"),
        ("creature_type_table", "creature_type_count"),
    ]:
        if first in extents:
            ranges.append((extents[first][0], extents[last][1]))
    ranges += [(int(e["address"], 16), int(e["address"], 16) + e["size"]) for e in entries]
    blocks = []
    for a, b in sorted(ranges):
        if blocks and a < blocks[-1][1]:
            blocks[-1][1] = max(b, blocks[-1][1])
        else:
            blocks.append([a, b])
    lines = [
        '#include "crimsonland_types.h"',
        '#include "crimsonland_metadata.h"',
        "quest_meta_cpp_t quest_meta_table[50];",
        "perk_meta_cpp_t perk_meta_table[128];",
        "bonus_meta_cpp_t bonus_meta_table[15];",
        "#include <stdint.h>",
        "#include <string.h>",
        "#if defined(__APPLE__)",
        '#define P "_"',
        "#else",
        '#define P ""',
        "#endif",
        'extern "C" {',
    ]
    resets = []
    reloc = []
    for i, (a, b) in enumerate(blocks):
        # Pointer-bearing storage expands on 64-bit hosts. Interior names below refer to first-record fields.
        size = b - a
        members = [e for e in entries if a <= int(e["address"], 16) < b]
        dynamic = {
            "effect_pool": "sizeof(effect_pool_t)",
            "creature_spawn_slot_table": "sizeof(creature_spawn_slot_t)*32",
            "effect_discard_entry": "sizeof(effect_entry_t)",
            "bonus_hud_slot_table": "sizeof(bonus_hud_slot_t)*17",
            "music_entry_table": "sizeof(music_entry_t)*128",
            "sfx_entry_table": "sizeof(sfx_entry_t)*128",
        }
        extent = str(max(size, 8))
        for e in members:
            if e["name"] in dynamic:
                needed = str(int(e["address"], 16) - a) + "+" + dynamic[e["name"]]
                extent = f"(({extent})>({needed})?({extent}):({needed}))"
        lines.append(f"alignas(16) unsigned char portable_data_{i}[{extent}];")
        resets.append(f"memset(portable_data_{i},0,sizeof(portable_data_{i}));")
        for e in entries:
            v = int(e["address"], 16)
            if not a <= v < b:
                continue
            name = e["name"]
            if not re.fullmatch(r"[A-Za-z_]\w*", name):
                continue
            lines.append(f'asm(".globl " P "{name}\\n.set " P "{name}, " P "portable_data_{i}+{v - a}\\n");')
            h = e.get("initializer_hex", "")
            if h and any(bytes.fromhex(h)):
                vals = ",".join(map(str, bytes.fromhex(h)))
                resets.append(
                    f"{{const unsigned char bytes[]={{ {vals} }}; memcpy(portable_data_{i}+{v - a},bytes,sizeof(bytes));}}",
                )
            if "initializer_target" in e:
                target = e["initializer_target"][1]
                reloc.append(
                    f"{{extern unsigned char {target}[]; uintptr_t p=(uintptr_t){target}; memcpy(portable_data_{i}+{v - a},&p,sizeof(p));}}",
                )
    for e, a, name in interiors:
        old_stride = {"quest_meta_table": 44, "perk_meta_table": 20, "bonus_meta_table": 20}[name]
        new_stride = {"quest_meta_table": 64, "perk_meta_table": 32, "bonus_meta_table": 32}[name]
        index, offset = divmod(int(e["address"], 16) - a, old_stride)
        offsets = (
            {0: 0, 4: 4, 8: 8, 12: 16, 16: 24, 20: 28, 24: 32, 28: 40, 32: 48, 36: 52, 40: 56}
            if name == "quest_meta_table"
            else {0: 0, 4: 8, 8: 16, 12: 20, 16: 24}
        )
        native = index * new_stride + offsets[offset]
        lines += [
            "#if UINTPTR_MAX > 0xffffffffu",
            f'asm(".globl " P "{e["name"]}\\n.set " P "{e["name"]}, " P "{name}+{native}\\n");',
            "#else",
            f'asm(".globl " P "{e["name"]}\\n.set " P "{e["name"]}, " P "{name}+{index * old_stride + offset}\\n");',
            "#endif",
        ]
    lines += ["void portable_reset_data() {", *resets, *reloc, "}", "}"]
    (out / "data.cpp").write_text("\n".join(lines) + "\n")
