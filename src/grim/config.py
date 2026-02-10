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
    config.data["ui_info_texts"] = 1
    # `config_init_defaults` (0x004028f0): defaults to 0 (enables blood splatter and "Bloody Mess" perk naming).
    config.data["fx_toggle"] = 0
    config.data["sfx_volume"] = 1.0
    config.data["music_volume"] = 1.0
    config.data["detail_preset"] = 5
    config.data["mouse_sensitivity"] = 1.0
    # Matches `config_init_defaults` (0x004028f0): Mouse2 for perk pick, Mouse3 for reload.
    config.data["keybind_pick_perk"] = 0x101
    config.data["keybind_reload"] = 0x102
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
        player_count = int(config.data.get("player_count", 1))
        if player_count < 1 or player_count > 4:
            config.data["player_count"] = 1
            config.save()
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
        # Patch up missing keybind defaults (older revisions left these as 0).
        keybind_patched = False
        if int(config.data.get("keybind_pick_perk", 0) or 0) == 0:
            config.data["keybind_pick_perk"] = 0x101
            keybind_patched = True
        if int(config.data.get("keybind_reload", 0) or 0) == 0:
            config.data["keybind_reload"] = 0x102
            keybind_patched = True
        if keybind_patched:
            config.save()
        # Patch up missing keybind defaults (older revisions left the entire keybind blob as 0).
        keybind_blob = config.data.get("keybinds")
        if isinstance(keybind_blob, (bytes, bytearray)) and len(keybind_blob) == 0x80:
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
                    config.data["keybinds"] = bytes(patched)
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
