from __future__ import annotations

from collections.abc import MutableMapping, Sequence

from .codec import KEYBINDS_BLOB_SIZE, UNKNOWN_248_SIZE

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
PLAYER_MODE_FLAG_KEYS = (
    "player_mode_flag_p1",
    "player_mode_flag_p2",
    "player_mode_flag_p3",
    "player_mode_flag_p4",
)
AIM_SCHEME_KEYS = (
    "aim_scheme_p1",
    "aim_scheme_p2",
    "aim_scheme_p3",
    "aim_scheme_p4",
)

# Native config stores one 16-dword bind block per player. The slot order is:
# move up/down/left/right, fire, two spare digital slots, torso left/right,
# aim axis Y/X, move axis Y/X, then three unused tail slots. P1/P2 mirror the
# original keyboard defaults; P3/P4 are rewrite-only extensions that preserve
# the same block shape so the blob helpers can treat every player uniformly.
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


def _block_uninitialized(values: Sequence[int]) -> bool:
    for idx in range(min(len(values), PLAYER_BIND_INPUT_DWORDS)):
        if int(values[idx]) != 0:
            return False
    return True


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


def _config_player_index(value: int) -> int:
    return max(0, min(3, int(value)))


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
    block = list(default_values if default_values is not None else default_player_keybind_block(0))
    limit = min(len(values), PLAYER_BIND_BLOCK_DWORDS)
    for idx in range(limit):
        block[idx] = int(values[idx]) & 0xFFFFFFFF
    for idx in range(PLAYER_BIND_BLOCK_DWORDS):
        dst = int(offset) + idx * 4
        blob[dst : dst + 4] = int(block[idx]).to_bytes(4, "little")


def aim_scheme_key(player_index: int) -> str:
    return AIM_SCHEME_KEYS[_config_player_index(player_index)]


def default_player_keybind_block(player_index: int) -> tuple[int, ...]:
    idx = int(player_index)
    if idx < 0:
        idx = 0
    if idx >= len(_DEFAULT_PLAYER_BIND_BLOCKS):
        idx = len(_DEFAULT_PLAYER_BIND_BLOCKS) - 1
    return _DEFAULT_PLAYER_BIND_BLOCKS[idx]


def hud_indicator_enabled_for_player(config_data: MutableMapping[str, object], *, player_index: int) -> bool:
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


def player_keybind_block(config_data: MutableMapping[str, object], *, player_index: int) -> tuple[int, ...]:
    """Return the 16-dword keybind block for player index 0..3.

    P1/P2 live in `keybinds` (0x80 bytes). P3/P4 are persisted in `unknown_248`
    reserved bytes to keep `crimson.cfg` layout unchanged.
    """

    idx = _config_player_index(player_index)
    if idx < 2:
        blob = _coerce_keybind_blob(config_data.get("keybinds"))
        block = _read_dword_block(blob, offset=idx * PLAYER_BIND_BLOCK_SIZE)
    else:
        blob = _coerce_unknown_248_blob(config_data.get("unknown_248"))
        offset = EXT_KEYBINDS_P3_OFFSET if idx == 2 else EXT_KEYBINDS_P4_OFFSET
        block = _read_dword_block(blob, offset=offset)
    if _block_uninitialized(block):
        return default_player_keybind_block(idx)
    return tuple(int(value) for value in block)


def player_keybind_value(config_data: MutableMapping[str, object], *, player_index: int, slot_index: int) -> int:
    slot = int(slot_index)
    if slot < 0 or slot >= PLAYER_BIND_BLOCK_DWORDS:
        return KEYBIND_UNBOUND_CODE
    block = player_keybind_block(config_data, player_index=int(player_index))
    if slot >= len(block):
        return KEYBIND_UNBOUND_CODE
    return int(block[slot])


def player_mode_flag_key(player_index: int) -> str:
    return PLAYER_MODE_FLAG_KEYS[_config_player_index(player_index)]


def set_hud_indicator_for_player(
    config_data: MutableMapping[str, object],
    *,
    player_index: int,
    enabled: bool,
) -> None:
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


def set_player_keybind_block(
    config_data: MutableMapping[str, object],
    *,
    player_index: int,
    values: Sequence[int],
) -> None:
    idx = _config_player_index(player_index)
    defaults = default_player_keybind_block(idx)
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


def set_player_keybind_value(
    config_data: MutableMapping[str, object],
    *,
    player_index: int,
    slot_index: int,
    value: int,
) -> None:
    slot = int(slot_index)
    if slot < 0 or slot >= PLAYER_BIND_BLOCK_DWORDS:
        return
    idx = _config_player_index(player_index)
    block = list(player_keybind_block(config_data, player_index=idx))
    while len(block) < PLAYER_BIND_BLOCK_DWORDS:
        block.append(int(default_player_keybind_block(idx)[len(block)]))
    block[slot] = int(value) & 0xFFFFFFFF
    set_player_keybind_block(config_data, player_index=idx, values=block)
