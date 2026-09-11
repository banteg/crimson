"""Compile fixture offsets with the same 32-bit compiler as the recovered source."""

import struct
from dataclasses import replace

from runner import PLAYER_FLOAT_FIELDS, e


def check_layout(config, out):
    expected = {
        "sizeof(player_state_t)": 0x360,
        "sizeof(creature_t)": 0x98,
        "sizeof(creature_spawn_slot_t)": 0x18,
        "sizeof(projectile_t)": 0x40,
        "sizeof(projectile_pool_t)": 0x60 * 0x40,
        "sizeof(sprite_effect_t)": 0x2C,
        "sizeof(particle_t)": 0x38,
        "sizeof(effect_template_t)": 0x3C,
        "sizeof(weapon_stats_t)": 0x7C,
        "offsetof(cvar_float_t, value)": 0xC,
    }
    for name, offset in PLAYER_FLOAT_FIELDS.items():
        expected[f"offsetof(player_state_t, {name})"] = offset
    for name, offset in {
        "aim": 0x50,
        "experience": 0xAC,
        "perk_counts": 0xB8,
        "weapon_id": 0x2C0,
        "reload_active": 0x2C8,
        "alt_weapon_id": 0x2DC,
        "alt_reload_active": 0x2E4,
        "auto_target": 0x320,
        "input": 0x32C,
    }.items():
        expected[f"offsetof(player_state_t, {name})"] = offset
    for i, name in enumerate(
        (
            "move_key_forward",
            "move_key_backward",
            "turn_key_left",
            "turn_key_right",
            "fire_key",
            "key_reserved_0",
            "key_reserved_1",
            "aim_key_left",
            "aim_key_right",
            "axis_aim_x",
            "axis_aim_y",
            "axis_move_x",
            "axis_move_y",
        ),
    ):
        expected[f"offsetof(player_input_t, {name})"] = 4 * i
    for owner, fields in {
        "creature_t": {"active": 0, "pos_x": 0x14, "pos_y": 0x18, "health": 0x24, "size": 0x34},
        "weapon_stats_t": {
            "shot_cooldown": 0x48,
            "reload_time": 0x4C,
            "spread_heat": 0x50,
            "shot_sfx_base_id": 0x58,
            "shot_sfx_variant_count": 0x5C,
            "reload_sfx_id": 0x60,
            "flags": 0x68,
            "pellet_count": 0x74,
        },
    }.items():
        for name, offset in fields.items():
            expected[f"offsetof({owner}, {name})"] = offset
    directory = out / "layout"
    directory.mkdir(exist_ok=True)
    source = '#include "crimsonland_gameplay.h"\n#include <stddef.h>\nextern "C" {\n'
    source += "unsigned int execution_offsets[] = {" + ", ".join(expected) + "};\n}\n"
    (directory / config.source).write_text(source)
    obj_path = e.match.compile_scratch(replace(config, directory=directory))
    obj = e.match.parse_coff_object(obj_path.read_bytes())
    symbol = next(symbol for symbol in obj.symbols if symbol.name == "_execution_offsets")
    raw = obj.sections[symbol.section_number - 1].data[symbol.value : symbol.value + 4 * len(expected)]
    observed = list(struct.unpack("<" + "I" * len(expected), raw))
    assert observed == list(expected.values()), (observed, expected)
    return expected
