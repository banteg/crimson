from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from construct import Byte, Bytes, Float32l, Int32ul, Struct

CRIMSON_CFG_NAME = "crimson.cfg"
CRIMSON_CFG_SIZE = 0x480

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
    "unknown_1c" / Bytes(0x28),
    "unknown_44" / Int32ul,
    "unknown_48" / Int32ul,
    "unknown_4c" / Bytes(0x20),
    "unknown_6c" / Int32ul,
    "texture_scale" / Float32l,
    "name_tag" / Bytes(12),
    "selected_name_slot" / Int32ul,
    "saved_name_index" / Int32ul,
    "saved_name_order" / Bytes(0x20),
    "saved_names" / Bytes(0xD8),
    "player_name" / Bytes(0x20),
    "player_name_len" / Int32ul,
    "unknown_1a4" / Int32ul,
    "unknown_1a8" / Int32ul,
    "unknown_1ac" / Int32ul,
    "unknown_1b0" / Int32ul,
    "unknown_1b4" / Int32ul,
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
    "full_version_flag" / Byte,
    "unknown_44a" / Bytes(2),
    "perk_prompt_counter" / Int32ul,
    "unknown_450" / Int32ul,
    "unknown_454" / Bytes(0x0C),
    "unknown_460" / Int32ul,
    "sfx_volume" / Float32l,
    "music_volume" / Float32l,
    "fx_toggle" / Byte,
    "score_load_gate" / Byte,
    "unknown_46e" / Byte,
    "unknown_46f" / Byte,
    "detail_preset" / Int32ul,
    "mouse_sensitivity" / Float32l,
    "keybind_pick_perk" / Int32ul,
    "keybind_reload" / Int32ul,
)


@dataclass(slots=True)
class CrimsonConfig:
    path: Path
    data: dict

    @property
    def texture_scale(self) -> float:
        return float(self.data["texture_scale"])

    @texture_scale.setter
    def texture_scale(self, value: float) -> None:
        self.data["texture_scale"] = float(value)

    @property
    def screen_bpp(self) -> int:
        return int(self.data["screen_bpp"])

    @screen_bpp.setter
    def screen_bpp(self, value: int) -> None:
        self.data["screen_bpp"] = int(value)

    @property
    def screen_width(self) -> int:
        return int(self.data["screen_width"])

    @screen_width.setter
    def screen_width(self, value: int) -> None:
        self.data["screen_width"] = int(value)

    @property
    def screen_height(self) -> int:
        return int(self.data["screen_height"])

    @screen_height.setter
    def screen_height(self, value: int) -> None:
        self.data["screen_height"] = int(value)

    @property
    def windowed_flag(self) -> int:
        return int(self.data["windowed_flag"])

    @windowed_flag.setter
    def windowed_flag(self, value: int) -> None:
        self.data["windowed_flag"] = int(value) & 0xFF

    def save(self) -> None:
        self.path.write_bytes(CRIMSON_CFG_STRUCT.build(self.data))


def default_crimson_cfg_data() -> dict:
    data = CRIMSON_CFG_STRUCT.parse(bytes(CRIMSON_CFG_SIZE))
    config = CrimsonConfig(path=Path("<memory>"), data=data)
    config.data["hud_indicators"] = b"\x01\x01"
    config.data["unknown_08"] = 8
    config.data["fx_detail_0"] = 1
    config.data["fx_detail_1"] = 1
    config.data["fx_detail_2"] = 1
    config.texture_scale = 1.0
    config.screen_bpp = 32
    config.screen_width = 1024
    config.screen_height = 768
    config.windowed_flag = 1
    config.data["player_count"] = 1
    config.data["game_mode"] = 1
    config.data["full_version_flag"] = 1
    config.data["fx_toggle"] = 1
    config.data["sfx_volume"] = 1.0
    config.data["music_volume"] = 1.0
    config.data["detail_preset"] = 5
    config.data["mouse_sensitivity"] = 1.0
    config.data["selected_name_slot"] = 0
    config.data["saved_name_index"] = 1
    config.data["unknown_1a4"] = 100
    config.data["unknown_1b0"] = 9000
    config.data["unknown_1b4"] = 27000

    saved_name_order = bytearray()
    for idx in range(8):
        saved_name_order += idx.to_bytes(4, "little")
    config.data["saved_name_order"] = bytes(saved_name_order)

    name_entry = b"default" + b"\x00" * (0x1B - len("default"))
    config.data["saved_names"] = name_entry * 8

    player_name = b"10tons" + b"\x00" * (0x20 - len("10tons"))
    config.data["player_name"] = player_name
    config.data["player_name_len"] = 0

    keybinds = [
        0x11,
        0x1F,
        0x1E,
        0x20,
        0x100,
        0x17E,
        0x17E,
        0x10,
        0x12,
        0x13F,
        0x140,
        0x141,
        0x153,
        0x17E,
        0x17E,
        0x17E,
        200,
        0xD0,
        0xCB,
        0xCD,
        0x9D,
        0x17E,
        0x17E,
        0xD3,
        0xD1,
        0x13F,
        0x140,
        0x141,
        0x153,
        0x17E,
        0x17E,
        0x17E,
    ]
    keybind_blob = b"".join(value.to_bytes(4, "little") for value in keybinds)
    if len(keybind_blob) != 0x80:
        raise ValueError(f"expected 0x80 bytes of keybinds, got {len(keybind_blob)}")
    config.data["keybinds"] = keybind_blob
    return data


def ensure_crimson_cfg(base_dir: Path) -> CrimsonConfig:
    path = base_dir / CRIMSON_CFG_NAME
    if path.exists():
        data = path.read_bytes()
        if len(data) != CRIMSON_CFG_SIZE:
            raise ValueError(f"{path} has unexpected size {len(data)} (expected {CRIMSON_CFG_SIZE})")
        parsed = CRIMSON_CFG_STRUCT.parse(data)
        config = CrimsonConfig(path=path, data=parsed)
        if (
            int(config.data.get("detail_preset", 0)) == 0
            and int(config.data.get("fx_detail_0", 0)) == 0
            and int(config.data.get("fx_detail_1", 0)) == 0
            and int(config.data.get("fx_detail_2", 0)) == 0
        ):
            config.data["fx_detail_0"] = 1
            config.data["fx_detail_1"] = 1
            config.data["fx_detail_2"] = 1
            config.data["detail_preset"] = 5
            config.save()
        return config
    parsed = default_crimson_cfg_data()
    config = CrimsonConfig(path=path, data=parsed)
    config.save()
    return config


def load_crimson_cfg(path: Path) -> CrimsonConfig:
    data = path.read_bytes()
    if len(data) != CRIMSON_CFG_SIZE:
        raise ValueError(f"{path} has unexpected size {len(data)} (expected {CRIMSON_CFG_SIZE})")
    parsed = CRIMSON_CFG_STRUCT.parse(data)
    return CrimsonConfig(path=path, data=parsed)


def apply_detail_preset(config: CrimsonConfig, preset: int | None = None) -> int:
    if preset is None:
        preset = int(config.data.get("detail_preset", 0))
    preset = int(preset)
    if preset < 1:
        preset = 1
    if preset > 5:
        preset = 5
    config.data["detail_preset"] = preset
    if preset <= 1:
        config.data["fx_detail_0"] = 0
        config.data["fx_detail_1"] = 0
        config.data["fx_detail_2"] = 0
    elif preset == 2:
        config.data["fx_detail_0"] = 0
        config.data["fx_detail_1"] = 0
    else:
        config.data["fx_detail_0"] = 1
        config.data["fx_detail_1"] = 1
        config.data["fx_detail_2"] = 1
    return preset
