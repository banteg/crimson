from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from construct import Byte, Bytes, Float32l, Int32ul, Struct

CRIMSON_CFG_NAME = "crimson.cfg"
CRIMSON_CFG_SIZE = 0x480
PLAYER_NAME_SIZE = 0x20
PLAYER_NAME_MAX_BYTES = PLAYER_NAME_SIZE - 1
KEYBINDS_BLOB_SIZE = 0x80
UNKNOWN_248_SIZE = 0x1F8
UNKNOWN_1C_SIZE = 0x28
UNKNOWN_4C_SIZE = 0x20
PLAYER_BIND_BLOCK_DWORDS = 0x10
PLAYER_BIND_BLOCK_SIZE = PLAYER_BIND_BLOCK_DWORDS * 4
PLAYER_BIND_INPUT_DWORDS = 0x0D
EXT_KEYBINDS_P3_OFFSET = 0x00
EXT_KEYBINDS_P4_OFFSET = EXT_KEYBINDS_P3_OFFSET + PLAYER_BIND_BLOCK_SIZE
EXT_HUD_INDICATOR_P3_OFFSET = EXT_KEYBINDS_P4_OFFSET + PLAYER_BIND_BLOCK_SIZE
EXT_HUD_INDICATOR_P4_OFFSET = EXT_HUD_INDICATOR_P3_OFFSET + 1
EXT_HUD_INDICATOR_UNSET = 0
EXT_HUD_INDICATOR_OFF = 1
EXT_HUD_INDICATOR_ON = 2
KEYBIND_UNBOUND_CODE = 0x17E

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
    "player_name" / Bytes(PLAYER_NAME_SIZE),
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
    # `crimsonland.exe` uses this byte as the "UI Info texts" toggle (it gates the perk prompt text).
    "ui_info_texts" / Byte,
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


_DEFAULT_PLAYER_BIND_BLOCKS: tuple[tuple[int, ...], ...] = (
    (
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
    ),
    (
        0xC8,
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
    ),
    (
        0x17,  # I
        0x25,  # K
        0x24,  # J
        0x26,  # L
        0x36,  # RShift
        0x17E,
        0x17E,
        0x16,  # U
        0x18,  # O
        0x17E,
        0x17E,
        0x17E,
        0x17E,
        0x17E,
        0x17E,
        0x17E,
    ),
    (
        0x131,  # JoysUp
        0x132,  # JoysDown
        0x133,  # JoysLeft
        0x134,  # JoysRight
        0x11F,  # Joys1
        0x17E,
        0x17E,
        0x17E,
        0x17E,
        0x140,
        0x13F,
        0x153,
        0x154,
        0x17E,
        0x17E,
        0x17E,
    ),
)


def _default_player_bind_block(player_index: int) -> tuple[int, ...]:
    idx = int(player_index)
    if idx < 0:
        idx = 0
    if idx >= len(_DEFAULT_PLAYER_BIND_BLOCKS):
        idx = len(_DEFAULT_PLAYER_BIND_BLOCKS) - 1
    return _DEFAULT_PLAYER_BIND_BLOCKS[idx]


def _coerce_keybind_blob(raw: object) -> bytearray:
    if not isinstance(raw, (bytes, bytearray)):
        return bytearray(KEYBINDS_BLOB_SIZE)
    data = bytearray(raw)
    if len(data) < KEYBINDS_BLOB_SIZE:
        data.extend(b"\x00" * (KEYBINDS_BLOB_SIZE - len(data)))
    if len(data) > KEYBINDS_BLOB_SIZE:
        del data[KEYBINDS_BLOB_SIZE:]
    return data


def _coerce_unknown_248_blob(raw: object) -> bytearray:
    if not isinstance(raw, (bytes, bytearray)):
        return bytearray(UNKNOWN_248_SIZE)
    data = bytearray(raw)
    if len(data) < UNKNOWN_248_SIZE:
        data.extend(b"\x00" * (UNKNOWN_248_SIZE - len(data)))
    if len(data) > UNKNOWN_248_SIZE:
        del data[UNKNOWN_248_SIZE:]
    return data


def _coerce_sized_blob(raw: object, *, size: int, fill: int = 0) -> bytes:
    if isinstance(raw, (bytes, bytearray)):
        data = bytearray(raw)
    else:
        data = bytearray([int(fill) & 0xFF] * int(size))
    if len(data) < size:
        data.extend(bytes([int(fill) & 0xFF]) * (size - len(data)))
    if len(data) > size:
        del data[size:]
    return bytes(data)


def _require_crimson_config(config: CrimsonConfig | None) -> CrimsonConfig | None:
    if config is None:
        return None
    if not isinstance(config, CrimsonConfig):
        raise TypeError(f"expected CrimsonConfig or None, got {type(config).__name__}")
    return config


def config_raw(config: CrimsonConfig | None, key: str, default: object = None) -> object:
    cfg = _require_crimson_config(config)
    if cfg is None:
        return default
    return cfg.data.get(str(key), default)


def config_int(config: CrimsonConfig | None, key: str, default: int = 0) -> int:
    value = config_raw(config, key, default)
    if value is None:
        return int(default)
    return int(value)


def config_float(config: CrimsonConfig | None, key: str, default: float = 0.0) -> float:
    value = config_raw(config, key, default)
    if value is None:
        return float(default)
    return float(value)


def config_bool(config: CrimsonConfig | None, key: str, *, default: bool = False) -> bool:
    return config_int(config, key, 1 if bool(default) else 0) != 0


def config_player_count(config: CrimsonConfig | None, default: int = 1) -> int:
    return config_int(config, "player_count", default)


def config_game_mode(config: CrimsonConfig | None, default: int = 1) -> int:
    return config_int(config, "game_mode", default)


def config_hardcore_flag(config: CrimsonConfig | None, *, default: bool = False) -> bool:
    return config_bool(config, "hardcore_flag", default=default)


def config_fx_detail(config: CrimsonConfig | None, *, level: int = 0, default: bool = False) -> bool:
    idx = int(level)
    if idx < 0:
        idx = 0
    if idx > 2:
        idx = 2
    return config_bool(config, f"fx_detail_{idx}", default=default)


def config_detail_preset(config: CrimsonConfig | None, default: int = 5) -> int:
    return config_int(config, "detail_preset", default)


def config_fx_toggle(config: CrimsonConfig | None, default: int = 0) -> int:
    return config_int(config, "fx_toggle", default)


def config_ui_info_texts(config: CrimsonConfig | None, *, default: bool = True) -> bool:
    return config_bool(config, "ui_info_texts", default=default)


def config_keybind_pick_perk(config: CrimsonConfig | None, default: int = 0x101) -> int:
    return config_int(config, "keybind_pick_perk", default)


def config_keybind_reload(config: CrimsonConfig | None, default: int = 0x102) -> int:
    return config_int(config, "keybind_reload", default)


def config_player_name(config: CrimsonConfig | None, default: str = "") -> str:
    cfg = _require_crimson_config(config)
    if cfg is None:
        return str(default)
    return str(cfg.player_name or default)


def config_quest_stage_major(config: CrimsonConfig | None, default: int = 0) -> int:
    return config_int(config, "quest_stage_major", default)


def config_quest_stage_minor(config: CrimsonConfig | None, default: int = 0) -> int:
    return config_int(config, "quest_stage_minor", default)


def config_quest_level(config: CrimsonConfig | None, default: str | None = None) -> str | None:
    value = config_raw(config, "quest_level", default)
    if isinstance(value, str):
        return value
    return default


def config_hud_indicators(config: CrimsonConfig | None, default: bytes = b"\x01\x01") -> bytes:
    value = config_raw(config, "hud_indicators", default)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return bytes(default)


def config_sfx_volume(config: CrimsonConfig | None, default: float = 1.0) -> float:
    return config_float(config, "sfx_volume", default)


def config_music_volume(config: CrimsonConfig | None, default: float = 1.0) -> float:
    return config_float(config, "music_volume", default)


def config_mouse_sensitivity(config: CrimsonConfig | None, default: float = 1.0) -> float:
    return config_float(config, "mouse_sensitivity", default)


def config_sound_disabled(config: CrimsonConfig | None, *, default: bool = False) -> bool:
    return config_bool(config, "sound_disable", default=default)


def config_music_disabled(config: CrimsonConfig | None, *, default: bool = False) -> bool:
    return config_bool(config, "music_disable", default=default)


def _read_dword_block(blob: bytes | bytearray, *, offset: int) -> tuple[int, ...]:
    values: list[int] = []
    for idx in range(PLAYER_BIND_BLOCK_DWORDS):
        src = int(offset) + idx * 4
        values.append(int.from_bytes(blob[src : src + 4], "little"))
    return tuple(values)


def _write_dword_block(
    blob: bytearray,
    *,
    offset: int,
    values: Sequence[int],
    default_values: Sequence[int] | None = None,
) -> None:
    block = list(default_values if default_values is not None else _default_player_bind_block(0))
    limit = min(len(values), PLAYER_BIND_BLOCK_DWORDS)
    for idx in range(limit):
        block[idx] = int(values[idx]) & 0xFFFFFFFF
    for idx in range(PLAYER_BIND_BLOCK_DWORDS):
        dst = int(offset) + idx * 4
        blob[dst : dst + 4] = int(block[idx]).to_bytes(4, "little")


def _block_uninitialized(values: Sequence[int]) -> bool:
    for idx in range(min(len(values), PLAYER_BIND_INPUT_DWORDS)):
        if int(values[idx]) != 0:
            return False
    return True


def player_keybind_block(config_data: dict, *, player_index: int) -> tuple[int, ...]:
    """Return the 16-dword keybind block for player index 0..3.

    P1/P2 live in `keybinds` (0x80 bytes). P3/P4 are persisted in `unknown_248`
    reserved bytes to keep `crimson.cfg` layout unchanged.
    """

    idx = max(0, min(3, int(player_index)))
    if idx < 2:
        blob = _coerce_keybind_blob(config_data.get("keybinds"))
        block = _read_dword_block(blob, offset=idx * PLAYER_BIND_BLOCK_SIZE)
    else:
        blob = _coerce_unknown_248_blob(config_data.get("unknown_248"))
        offset = EXT_KEYBINDS_P3_OFFSET if idx == 2 else EXT_KEYBINDS_P4_OFFSET
        block = _read_dword_block(blob, offset=offset)
    if _block_uninitialized(block):
        return _default_player_bind_block(idx)
    return tuple(int(value) for value in block)


def set_player_keybind_block(config_data: dict, *, player_index: int, values: Sequence[int]) -> None:
    idx = max(0, min(3, int(player_index)))
    defaults = _default_player_bind_block(idx)
    if idx < 2:
        blob = _coerce_keybind_blob(config_data.get("keybinds"))
        _write_dword_block(
            blob,
            offset=idx * PLAYER_BIND_BLOCK_SIZE,
            values=values,
            default_values=defaults,
        )
        config_data["keybinds"] = bytes(blob)
        return
    blob = _coerce_unknown_248_blob(config_data.get("unknown_248"))
    offset = EXT_KEYBINDS_P3_OFFSET if idx == 2 else EXT_KEYBINDS_P4_OFFSET
    _write_dword_block(
        blob,
        offset=offset,
        values=values,
        default_values=defaults,
    )
    config_data["unknown_248"] = bytes(blob)


def default_player_keybind_block(player_index: int) -> tuple[int, ...]:
    return _default_player_bind_block(int(player_index))


def player_keybind_value(config_data: dict, *, player_index: int, slot_index: int) -> int:
    slot = int(slot_index)
    if slot < 0 or slot >= PLAYER_BIND_BLOCK_DWORDS:
        return KEYBIND_UNBOUND_CODE
    block = player_keybind_block(config_data, player_index=int(player_index))
    if slot >= len(block):
        return KEYBIND_UNBOUND_CODE
    return int(block[slot])


def set_player_keybind_value(
    config_data: dict,
    *,
    player_index: int,
    slot_index: int,
    value: int,
) -> None:
    slot = int(slot_index)
    if slot < 0 or slot >= PLAYER_BIND_BLOCK_DWORDS:
        return
    idx = max(0, min(3, int(player_index)))
    block = list(player_keybind_block(config_data, player_index=idx))
    while len(block) < PLAYER_BIND_BLOCK_DWORDS:
        block.append(int(_default_player_bind_block(idx)[len(block)]))
    block[slot] = int(value) & 0xFFFFFFFF
    set_player_keybind_block(config_data, player_index=idx, values=block)


def hud_indicator_enabled_for_player(config_data: dict, *, player_index: int) -> bool:
    idx = int(player_index)
    if idx < 0:
        return False
    if idx < 2:
        raw = config_data.get("hud_indicators", b"\x01\x01")
        if not isinstance(raw, (bytes, bytearray)):
            return True
        if idx >= len(raw):
            return True
        return bool(raw[idx])

    blob = _coerce_unknown_248_blob(config_data.get("unknown_248"))
    offset = EXT_HUD_INDICATOR_P3_OFFSET if idx == 2 else EXT_HUD_INDICATOR_P4_OFFSET
    value = int(blob[offset]) if 0 <= offset < len(blob) else EXT_HUD_INDICATOR_UNSET
    if value == EXT_HUD_INDICATOR_OFF:
        return False
    if value == EXT_HUD_INDICATOR_ON:
        return True
    return True


def set_hud_indicator_for_player(config_data: dict, *, player_index: int, enabled: bool) -> None:
    idx = int(player_index)
    if idx < 0:
        return
    if idx < 2:
        raw = config_data.get("hud_indicators", b"\x01\x01")
        values = bytearray(raw) if isinstance(raw, (bytes, bytearray)) else bytearray(b"\x01\x01")
        if len(values) < 2:
            values.extend(b"\x01" * (2 - len(values)))
        values[idx] = 1 if bool(enabled) else 0
        config_data["hud_indicators"] = bytes(values[:2])
        return

    blob = _coerce_unknown_248_blob(config_data.get("unknown_248"))
    offset = EXT_HUD_INDICATOR_P3_OFFSET if idx == 2 else EXT_HUD_INDICATOR_P4_OFFSET
    if 0 <= offset < len(blob):
        blob[offset] = EXT_HUD_INDICATOR_ON if bool(enabled) else EXT_HUD_INDICATOR_OFF
    config_data["unknown_248"] = bytes(blob)


@dataclass(slots=True)
class CrimsonConfig:
    path: Path
    data: dict

    def raw_value(self, key: str, default: object = None) -> object:
        return self.data.get(str(key), default)

    def set_raw_value(self, key: str, value: object) -> None:
        self.data[str(key)] = value

    def int_value(self, key: str, default: int = 0) -> int:
        value = self.raw_value(key, default)
        if value is None:
            return int(default)
        return int(value)

    def set_int_value(self, key: str, value: int) -> None:
        self.data[str(key)] = int(value)

    def float_value(self, key: str, default: float = 0.0) -> float:
        value = self.raw_value(key, default)
        if value is None:
            return float(default)
        return float(value)

    def set_float_value(self, key: str, value: float) -> None:
        self.data[str(key)] = float(value)

    def bool_value(self, key: str, *, default: bool = False) -> bool:
        return self.int_value(str(key), 1 if bool(default) else 0) != 0

    def set_bool_value(self, key: str, enabled: bool) -> None:
        self.data[str(key)] = 1 if bool(enabled) else 0

    def blob_value(self, key: str, *, size: int, default: bytes | bytearray | None = None, fill: int = 0) -> bytes:
        raw = self.raw_value(key, default)
        if default is None:
            raw = self.raw_value(key)
        return _coerce_sized_blob(raw, size=int(size), fill=int(fill))

    def set_blob_value(self, key: str, value: bytes | bytearray, *, size: int, fill: int = 0) -> None:
        self.data[str(key)] = _coerce_sized_blob(value, size=int(size), fill=int(fill))

    @property
    def player_count(self) -> int:
        return self.int_value("player_count", 1)

    @player_count.setter
    def player_count(self, value: int) -> None:
        self.set_int_value("player_count", value)

    @property
    def game_mode(self) -> int:
        return self.int_value("game_mode", 1)

    @game_mode.setter
    def game_mode(self, value: int) -> None:
        self.set_int_value("game_mode", value)

    @property
    def hardcore(self) -> bool:
        return self.bool_value("hardcore_flag", default=False)

    @hardcore.setter
    def hardcore(self, enabled: bool) -> None:
        self.set_bool_value("hardcore_flag", enabled)

    def fx_detail(self, *, level: int = 0, default: bool = False) -> bool:
        idx = max(0, min(2, int(level)))
        return self.bool_value(f"fx_detail_{idx}", default=default)

    def set_fx_detail(self, *, level: int, enabled: bool) -> None:
        idx = max(0, min(2, int(level)))
        self.set_bool_value(f"fx_detail_{idx}", enabled)

    @property
    def detail_preset(self) -> int:
        return self.int_value("detail_preset", 5)

    @detail_preset.setter
    def detail_preset(self, value: int) -> None:
        self.set_int_value("detail_preset", value)

    @property
    def fx_toggle(self) -> int:
        return self.int_value("fx_toggle", 0)

    @fx_toggle.setter
    def fx_toggle(self, value: int) -> None:
        self.set_int_value("fx_toggle", value)

    @property
    def ui_info_texts(self) -> bool:
        return self.bool_value("ui_info_texts", default=True)

    @ui_info_texts.setter
    def ui_info_texts(self, enabled: bool) -> None:
        self.set_bool_value("ui_info_texts", enabled)

    @property
    def keybind_pick_perk(self) -> int:
        return self.int_value("keybind_pick_perk", 0x101)

    @keybind_pick_perk.setter
    def keybind_pick_perk(self, value: int) -> None:
        self.set_int_value("keybind_pick_perk", value)

    @property
    def keybind_reload(self) -> int:
        return self.int_value("keybind_reload", 0x102)

    @keybind_reload.setter
    def keybind_reload(self, value: int) -> None:
        self.set_int_value("keybind_reload", value)

    @property
    def quest_stage_major(self) -> int:
        return self.int_value("quest_stage_major", 0)

    @quest_stage_major.setter
    def quest_stage_major(self, value: int) -> None:
        self.set_int_value("quest_stage_major", value)

    @property
    def quest_stage_minor(self) -> int:
        return self.int_value("quest_stage_minor", 0)

    @quest_stage_minor.setter
    def quest_stage_minor(self, value: int) -> None:
        self.set_int_value("quest_stage_minor", value)

    @property
    def quest_level(self) -> str | None:
        value = self.raw_value("quest_level")
        if isinstance(value, str):
            return value
        return None

    @quest_level.setter
    def quest_level(self, value: str | None) -> None:
        if value is None:
            self.data.pop("quest_level", None)
            return
        self.set_raw_value("quest_level", str(value))

    @property
    def hud_indicators(self) -> bytes:
        return self.blob_value("hud_indicators", size=2, default=b"\x01\x01", fill=1)

    @hud_indicators.setter
    def hud_indicators(self, value: bytes | bytearray) -> None:
        self.set_blob_value("hud_indicators", value, size=2, fill=1)

    @property
    def unknown_1c(self) -> bytes:
        return self.blob_value("unknown_1c", size=UNKNOWN_1C_SIZE, default=bytes(UNKNOWN_1C_SIZE))

    @unknown_1c.setter
    def unknown_1c(self, value: bytes | bytearray) -> None:
        self.set_blob_value("unknown_1c", value, size=UNKNOWN_1C_SIZE)

    @property
    def unknown_44(self) -> int:
        return self.int_value("unknown_44", 0)

    @unknown_44.setter
    def unknown_44(self, value: int) -> None:
        self.set_int_value("unknown_44", value)

    @property
    def unknown_48(self) -> int:
        return self.int_value("unknown_48", 0)

    @unknown_48.setter
    def unknown_48(self, value: int) -> None:
        self.set_int_value("unknown_48", value)

    @property
    def unknown_4c(self) -> bytes:
        return self.blob_value("unknown_4c", size=UNKNOWN_4C_SIZE, default=bytes(UNKNOWN_4C_SIZE))

    @unknown_4c.setter
    def unknown_4c(self, value: bytes | bytearray) -> None:
        self.set_blob_value("unknown_4c", value, size=UNKNOWN_4C_SIZE)

    @property
    def sfx_volume(self) -> float:
        return self.float_value("sfx_volume", 1.0)

    @sfx_volume.setter
    def sfx_volume(self, value: float) -> None:
        self.set_float_value("sfx_volume", value)

    @property
    def music_volume(self) -> float:
        return self.float_value("music_volume", 1.0)

    @music_volume.setter
    def music_volume(self, value: float) -> None:
        self.set_float_value("music_volume", value)

    @property
    def mouse_sensitivity(self) -> float:
        return self.float_value("mouse_sensitivity", 1.0)

    @mouse_sensitivity.setter
    def mouse_sensitivity(self, value: float) -> None:
        self.set_float_value("mouse_sensitivity", value)

    @property
    def sound_disabled(self) -> bool:
        return self.bool_value("sound_disable", default=False)

    @sound_disabled.setter
    def sound_disabled(self, disabled: bool) -> None:
        self.set_bool_value("sound_disable", disabled)

    @property
    def music_disabled(self) -> bool:
        return self.bool_value("music_disable", default=False)

    @music_disabled.setter
    def music_disabled(self, disabled: bool) -> None:
        self.set_bool_value("music_disable", disabled)

    @property
    def keybinds(self) -> bytes:
        return self.blob_value("keybinds", size=KEYBINDS_BLOB_SIZE, default=bytes(KEYBINDS_BLOB_SIZE))

    @keybinds.setter
    def keybinds(self, value: bytes | bytearray) -> None:
        self.set_blob_value("keybinds", value, size=KEYBINDS_BLOB_SIZE)

    def player_keybind_block(self, *, player_index: int) -> tuple[int, ...]:
        return player_keybind_block(self.data, player_index=player_index)

    def set_player_keybind_block(self, *, player_index: int, values: Sequence[int]) -> None:
        set_player_keybind_block(self.data, player_index=player_index, values=values)

    def player_keybind_value(self, *, player_index: int, slot_index: int) -> int:
        return player_keybind_value(self.data, player_index=player_index, slot_index=slot_index)

    def set_player_keybind_value(self, *, player_index: int, slot_index: int, value: int) -> None:
        set_player_keybind_value(self.data, player_index=player_index, slot_index=slot_index, value=value)

    def hud_indicator_enabled_for_player(self, *, player_index: int) -> bool:
        return hud_indicator_enabled_for_player(self.data, player_index=player_index)

    def set_hud_indicator_for_player(self, *, player_index: int, enabled: bool) -> None:
        set_hud_indicator_for_player(self.data, player_index=player_index, enabled=enabled)

    # Backwards-compatible aliases while callers migrate to properties.
    def player_name_value(self, default: str = "") -> str:
        value = self.player_name
        if value:
            return value
        return str(default)

    def player_count_value(self, default: int = 1) -> int:
        return self.int_value("player_count", default)

    def set_player_count(self, value: int) -> None:
        self.player_count = value

    def game_mode_id(self, default: int = 1) -> int:
        return self.int_value("game_mode", default)

    def set_game_mode_id(self, value: int) -> None:
        self.game_mode = value

    def hardcore_enabled(self, *, default: bool = False) -> bool:
        return self.bool_value("hardcore_flag", default=default)

    def set_hardcore_enabled(self, enabled: bool) -> None:
        self.hardcore = enabled

    def fx_detail_enabled(self, *, level: int = 0, default: bool = False) -> bool:
        return self.fx_detail(level=level, default=default)

    def set_fx_detail_enabled(self, *, level: int, enabled: bool) -> None:
        self.set_fx_detail(level=level, enabled=enabled)

    def detail_preset_value(self, default: int = 5) -> int:
        return self.int_value("detail_preset", default)

    def set_detail_preset(self, value: int) -> None:
        self.detail_preset = value

    def fx_toggle_value(self, default: int = 0) -> int:
        return self.int_value("fx_toggle", default)

    def set_fx_toggle(self, value: int) -> None:
        self.fx_toggle = value

    def ui_info_texts_enabled(self, *, default: bool = True) -> bool:
        return self.bool_value("ui_info_texts", default=default)

    def set_ui_info_texts_enabled(self, enabled: bool) -> None:
        self.ui_info_texts = enabled

    def keybind_pick_perk_value(self, default: int = 0x101) -> int:
        return self.int_value("keybind_pick_perk", default)

    def set_keybind_pick_perk(self, value: int) -> None:
        self.keybind_pick_perk = value

    def keybind_reload_value(self, default: int = 0x102) -> int:
        return self.int_value("keybind_reload", default)

    def set_keybind_reload(self, value: int) -> None:
        self.keybind_reload = value

    def quest_stage_major_value(self, default: int = 0) -> int:
        return self.int_value("quest_stage_major", default)

    def set_quest_stage_major(self, value: int) -> None:
        self.quest_stage_major = value

    def quest_stage_minor_value(self, default: int = 0) -> int:
        return self.int_value("quest_stage_minor", default)

    def set_quest_stage_minor(self, value: int) -> None:
        self.quest_stage_minor = value

    def quest_level_value(self, default: str | None = None) -> str | None:
        value = self.quest_level
        if value is None:
            return default
        return value

    def set_quest_level(self, value: str) -> None:
        self.quest_level = value

    def hud_indicators_value(self, default: bytes = b"\x01\x01") -> bytes:
        return self.blob_value("hud_indicators", size=2, default=default, fill=1)

    def set_hud_indicators_value(self, value: bytes | bytearray) -> None:
        self.hud_indicators = value

    def sfx_volume_value(self, default: float = 1.0) -> float:
        return self.float_value("sfx_volume", default)

    def set_sfx_volume_value(self, value: float) -> None:
        self.sfx_volume = value

    def music_volume_value(self, default: float = 1.0) -> float:
        return self.float_value("music_volume", default)

    def set_music_volume_value(self, value: float) -> None:
        self.music_volume = value

    def mouse_sensitivity_value(self, default: float = 1.0) -> float:
        return self.float_value("mouse_sensitivity", default)

    def set_mouse_sensitivity_value(self, value: float) -> None:
        self.mouse_sensitivity = value

    def keybinds_blob(self) -> bytes:
        return self.keybinds

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

    @property
    def player_name(self) -> str:
        raw = bytes(self.data["player_name"])
        return raw.split(b"\x00", 1)[0].decode("latin-1", errors="ignore")

    @player_name.setter
    def player_name(self, value: str) -> None:
        self.set_player_name(value)

    def set_player_name(self, name: str) -> None:
        # Config stores a 0x20 buffer (latin-1) and a mirrored length integer.
        encoded = name.encode("latin-1", errors="ignore")[:PLAYER_NAME_MAX_BYTES]
        buf = bytearray(PLAYER_NAME_SIZE)
        buf[: len(encoded)] = encoded
        buf[min(len(encoded), PLAYER_NAME_MAX_BYTES)] = 0

        # Match `highscore_save_record` trimming: strip trailing spaces in-place.
        end = buf.index(0)
        i = end - 1
        while i > 0 and buf[i] == 0x20:
            buf[i] = 0
            i -= 1

        self.data["player_name"] = bytes(buf)
        self.data["player_name_len"] = int(len(encoded))

    def save(self) -> None:
        self.path.write_bytes(CRIMSON_CFG_STRUCT.build(self.data))


def default_crimson_cfg_data() -> dict:
    data = CRIMSON_CFG_STRUCT.parse(bytes(CRIMSON_CFG_SIZE))
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
    config.fx_toggle = 0
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

    for idx in range(4):
        set_player_keybind_block(config.data, player_index=idx, values=_default_player_bind_block(idx))
    return data


def ensure_crimson_cfg(base_dir: Path) -> CrimsonConfig:
    path = base_dir / CRIMSON_CFG_NAME
    if path.exists():
        data = path.read_bytes()
        if len(data) != CRIMSON_CFG_SIZE:
            raise ValueError(f"{path} has unexpected size {len(data)} (expected {CRIMSON_CFG_SIZE})")
        parsed = CRIMSON_CFG_STRUCT.parse(data)
        config = CrimsonConfig(path=path, data=parsed)
        # Patch up configs produced by older revisions of this project.
        # `crimsonland.exe` expects player_count in [1..4], but our repo historically had 0 here.
        player_count = config.player_count
        if player_count < 1 or player_count > 4:
            config.player_count = 1
            config.save()
        if (
            config.detail_preset == 0
            and not config.fx_detail(level=0, default=False)
            and not config.fx_detail(level=1, default=False)
            and not config.fx_detail(level=2, default=False)
        ):
            config.set_fx_detail(level=0, enabled=True)
            config.set_fx_detail(level=1, enabled=True)
            config.set_fx_detail(level=2, enabled=True)
            config.detail_preset = 5
            config.save()
        # Patch up missing keybind defaults (older revisions left these as 0).
        keybind_patched = False
        if config.keybind_pick_perk == 0:
            config.keybind_pick_perk = 0x101
            keybind_patched = True
        if config.keybind_reload == 0:
            config.keybind_reload = 0x102
            keybind_patched = True
        if keybind_patched:
            config.save()
        # Patch up missing keybind defaults (older revisions left the entire keybind blob as 0).
        keybind_blob = config.keybinds
        default_keybinds = default_crimson_cfg_data().get("keybinds")
        if isinstance(default_keybinds, (bytes, bytearray)) and len(default_keybinds) == 0x80:
            patched = bytearray(keybind_blob)
            changed = False
            for offset in range(0, 0x80, 4):
                value = int.from_bytes(patched[offset : offset + 4], "little")
                if value != 0:
                    continue
                patched[offset : offset + 4] = default_keybinds[offset : offset + 4]
                changed = True
            if changed:
                config.keybinds = bytes(patched)
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
        preset = config.detail_preset
    preset = int(preset)
    if preset < 1:
        preset = 1
    if preset > 5:
        preset = 5
    config.detail_preset = preset
    if preset <= 1:
        config.set_fx_detail(level=0, enabled=False)
        config.set_fx_detail(level=1, enabled=False)
        config.set_fx_detail(level=2, enabled=False)
    elif preset == 2:
        config.set_fx_detail(level=0, enabled=False)
        config.set_fx_detail(level=1, enabled=False)
    else:
        config.set_fx_detail(level=0, enabled=True)
        config.set_fx_detail(level=1, enabled=True)
        config.set_fx_detail(level=2, enabled=True)
    return preset
