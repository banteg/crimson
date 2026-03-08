from __future__ import annotations

from pathlib import Path

from .codec import CRIMSON_CFG_SIZE, parse_crimson_cfg
from .controls import default_player_keybind_block, set_player_keybind_block
from .model import CrimsonConfig


def default_crimson_cfg_data() -> dict:
    data = parse_crimson_cfg(bytes(CRIMSON_CFG_SIZE))
    config = CrimsonConfig(path=Path("<memory>"), data=data)
    config.hud_indicators = b"\x01\x01"
    config.data["unknown_08"] = 8
    config.set_fx_detail(level=0, enabled=True)
    config.set_fx_detail(level=1, enabled=True)
    config.set_fx_detail(level=2, enabled=True)
    config.texture_scale = 1.0
    config.screen_bpp = 32
    config.screen_width = 1024
    config.screen_height = 768
    config.windowed_flag = 1
    config.player_count = 1
    config.game_mode = 1
    config.ui_info_texts = True
    # `config_init_defaults` (0x004028f0): defaults to 0 (enables blood splatter and "Bloody Mess" perk naming).
    config.gore_disabled = 0
    config.sfx_volume = 1.0
    config.music_volume = 1.0
    config.detail_preset = 5
    config.mouse_sensitivity = 1.0
    # Matches `config_init_defaults` (0x004028f0): Mouse2 for perk pick, Mouse3 for reload.
    config.keybind_pick_perk = 0x101
    config.keybind_reload = 0x102
    config.data["selected_name_slot"] = 0
    config.data["saved_name_index"] = 1
    config.data["unknown_1a4"] = 100
    config.data["aim_pov_right"] = 9000
    config.data["aim_pov_left"] = 27000
    config.data["player_mode_flag_p1"] = 2
    config.data["player_mode_flag_p2"] = 2
    config.data["player_mode_flag_p3"] = 0
    config.data["player_mode_flag_p4"] = 0
    config.data["aim_scheme_p1"] = 0
    config.data["aim_scheme_p2"] = 0
    config.data["aim_scheme_p3"] = 0
    config.data["aim_scheme_p4"] = 0

    saved_name_order = bytearray()
    for idx in range(8):
        saved_name_order += idx.to_bytes(4, "little")
    config.data["saved_name_order"] = bytes(saved_name_order)

    name_entry = b"default" + b"\x00" * (0x1B - len("default"))
    config.data["saved_names"] = name_entry * 8

    player_name = b"10tons" + b"\x00" * (0x20 - len("10tons"))
    config.data["player_name"] = player_name
    config.data["player_name_len"] = 0

    for idx in range(4):
        set_player_keybind_block(config.data, player_index=idx, values=default_player_keybind_block(idx))
    return data
