from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from construct import Byte, Bytes, Float32l, Int32ul, Struct

CRIMSON_CFG_NAME = "crimson.cfg"
CRIMSON_CFG_SIZE = 0x480
PLAYER_NAME_SIZE = 0x20
PLAYER_NAME_MAX_BYTES = PLAYER_NAME_SIZE - 1
KEYBINDS_BLOB_SIZE = 0x80
UNKNOWN_248_SIZE = 0x1F8

CRIMSON_CFG_STRUCT = Struct(
    "sound_disable" / Byte,
    "music_disable" / Byte,
    "highscore_date_mode" / Byte,
    "highscore_duplicate_mode" / Byte,
    "hud_indicators" / Bytes(2),
    "unknown_06" / Bytes(2),
    "unknown_08" / Int32ul,
    "unknown_0c" / Bytes(2),
    "fx_detail_0" / Byte,
    "unknown_0f" / Byte,
    "fx_detail_1" / Byte,
    "fx_detail_2" / Byte,
    "unknown_12" / Bytes(2),
    "player_count" / Int32ul,
    "game_mode" / Int32ul,
    "player_mode_flag_p1" / Int32ul,
    "player_mode_flag_p2" / Int32ul,
    "player_mode_flag_p3" / Int32ul,
    "player_mode_flag_p4" / Int32ul,
    "player_mode_flags_reserved" / Bytes(0x18),
    "aim_scheme_p1" / Int32ul,
    "aim_scheme_p2" / Int32ul,
    "aim_scheme_p3" / Int32ul,
    "aim_scheme_p4" / Int32ul,
    "aim_schemes_reserved" / Bytes(0x18),
    "unknown_6c" / Int32ul,
    "texture_scale" / Float32l,
    "name_tag" / Bytes(12),
    "selected_name_slot" / Int32ul,
    "saved_name_index" / Int32ul,
    "saved_name_order" / Bytes(0x20),
    "saved_names" / Bytes(0xD8),
    "player_name" / Bytes(PLAYER_NAME_SIZE),
    "player_name_len" / Int32ul,
    "unknown_1a4" / Int32ul,
    "unknown_1a8" / Int32ul,
    "unknown_1ac" / Int32ul,
    "aim_pov_right" / Int32ul,
    "aim_pov_left" / Int32ul,
    "screen_bpp" / Int32ul,
    "screen_width" / Int32ul,
    "screen_height" / Int32ul,
    "windowed_flag" / Byte,
    "unknown_1c5" / Bytes(3),
    "keybinds" / Bytes(0x80),
    "unknown_248" / Bytes(0x1F8),
    "unknown_440" / Int32ul,
    "unknown_444" / Int32ul,
    "hardcore_flag" / Byte,
    "ui_info_texts" / Byte,
    "unknown_44a" / Bytes(2),
    "perk_prompt_counter" / Int32ul,
    "unknown_450" / Int32ul,
    "unknown_454" / Bytes(0x0C),
    "unknown_460" / Int32ul,
    "sfx_volume" / Float32l,
    "music_volume" / Float32l,
    "gore_disabled" / Byte,
    "score_load_gate" / Byte,
    "unknown_46e" / Byte,
    "unknown_46f" / Byte,
    "detail_preset" / Int32ul,
    "mouse_sensitivity" / Float32l,
    "keybind_pick_perk" / Int32ul,
    "keybind_reload" / Int32ul,
)

_CRIMSON_CFG_FIELD_NAMES = tuple(sub.name for sub in CRIMSON_CFG_STRUCT.subcons if sub.name)


def build_crimson_cfg(data: Mapping[str, object]) -> bytes:
    return cast(bytes, CRIMSON_CFG_STRUCT.build(dict(data)))


def iter_crimson_cfg_field_names() -> tuple[str, ...]:
    return _CRIMSON_CFG_FIELD_NAMES


def parse_crimson_cfg(data: bytes) -> dict:
    return cast(dict, CRIMSON_CFG_STRUCT.parse(data))
