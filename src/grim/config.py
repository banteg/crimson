from __future__ import annotations

from collections.abc import Sequence
from enum import IntEnum
from pathlib import Path
from typing import Any, TypeAlias, cast

import msgspec
from construct import Array, Byte, Bytes, Float32l, Int32ul, Struct

from crimson.aim_schemes import AimScheme, aim_scheme_from_value
from crimson.game_modes import GameMode
from crimson.movement_controls import MovementControlType, movement_control_type_from_value
from crimson.quests.level import QuestLevel

CRIMSON_CFG_NAME = "crimson.cfg"
CRIMSON_CFG_SIZE = 0x480
PLAYER_NAME_SIZE = 0x20
PLAYER_NAME_MAX_BYTES = PLAYER_NAME_SIZE - 1
SAVED_NAME_SLOT_COUNT = 8
SAVED_NAME_ENTRY_SIZE = 0x1B
SAVED_NAMES_BLOB_SIZE = SAVED_NAME_SLOT_COUNT * SAVED_NAME_ENTRY_SIZE
KEYBINDS_BLOB_SIZE = 0x80
UNKNOWN_248_SIZE = 0x1F8
PLAYER_BIND_BLOCK_DWORDS = 0x10
PLAYER_BIND_BLOCK_SIZE = PLAYER_BIND_BLOCK_DWORDS * 4
PLAYER_BIND_INPUT_DWORDS = 0x0D
EXT_DIRECTION_ARROW_FLAG_COUNT = 2
EXTENDED_RESERVED_GAP_SIZE = UNKNOWN_248_SIZE - 2 * PLAYER_BIND_BLOCK_SIZE - EXT_DIRECTION_ARROW_FLAG_COUNT
EXT_DIRECTION_ARROW_UNSET = 0
EXT_DIRECTION_ARROW_OFF = 1
EXT_DIRECTION_ARROW_ON = 2
KEYBIND_UNBOUND_CODE = 0x17E

PlayerKeybindBlock: TypeAlias = tuple[
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
]

CRIMSON_CFG_STRUCT = Struct(
    "sound_disable" / Byte,
    "music_disable" / Byte,
    "highscore_date_mode" / Byte,
    "highscore_duplicate_mode" / Byte,
    "direction_arrow_flags" / Bytes(2),
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
    "saved_names" / Bytes(SAVED_NAMES_BLOB_SIZE),
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
    "keybinds" / Bytes(KEYBINDS_BLOB_SIZE),
    # The original wire format leaves this 0x1F8-byte gap uninterpreted.
    # The Python port uses the front of it for P3/P4 control bindings and
    # their direction-arrow flags, while preserving the remaining bytes.
    "extended_keybinds_p3" / Array(PLAYER_BIND_BLOCK_DWORDS, Int32ul),
    "extended_keybinds_p4" / Array(PLAYER_BIND_BLOCK_DWORDS, Int32ul),
    "extended_direction_arrow_flags" / Array(EXT_DIRECTION_ARROW_FLAG_COUNT, Byte),
    "extended_reserved_gap" / Bytes(EXTENDED_RESERVED_GAP_SIZE),
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
        0x17,
        0x25,
        0x24,
        0x26,
        0x36,
        0x17E,
        0x17E,
        0x16,
        0x18,
        0x17E,
        0x17E,
        0x17E,
        0x17E,
        0x17E,
        0x17E,
        0x17E,
    ),
    (
        0x131,
        0x132,
        0x133,
        0x134,
        0x11F,
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

_DEFAULT_PROFILE_NAME = "10tons"
_DEFAULT_SAVED_NAMES: tuple[str, str, str, str, str, str, str, str] = (
    "default",
    "default",
    "default",
    "default",
    "default",
    "default",
    "default",
    "default",
)


class HighScoreDateMode(IntEnum):
    ALL_TIME = 0
    MONTH = 1
    WEEK = 2
    DAY = 3


class CrimsonDisplayConfig(msgspec.Struct):
    width: int
    height: int
    windowed: bool
    bpp: int
    texture_scale: float
    mouse_sensitivity: float
    detail_preset: int
    fx_detail: tuple[bool, bool, bool]
    gore_disabled: int

    def fx_detail_enabled(self, level: int, default: bool = False) -> bool:
        idx = _clamp(level, minimum=0, maximum=2)
        if idx >= len(self.fx_detail):
            return bool(default)
        return bool(self.fx_detail[idx])

    def set_fx_detail(self, level: int, enabled: bool) -> None:
        idx = _clamp(level, minimum=0, maximum=2)
        values = list(self.fx_detail)
        while len(values) < 3:
            values.append(False)
        values[idx] = bool(enabled)
        self.fx_detail = (bool(values[0]), bool(values[1]), bool(values[2]))


class CrimsonAudioConfig(msgspec.Struct):
    sound_disabled: bool
    music_disabled: bool
    sfx_volume: float
    music_volume: float


class CrimsonGameplayConfig(msgspec.Struct):
    mode: GameMode
    player_count: int
    hardcore: bool
    quest_level: QuestLevel | None
    show_info_texts: bool


class CrimsonProfileConfig(msgspec.Struct):
    player_name: str
    player_name_input_len: int
    saved_name_count: int
    selected_saved_name_slot: int
    saved_names: tuple[str, str, str, str, str, str, str, str]
    show_internet_scores: bool
    score_date_mode: HighScoreDateMode

    def set_player_name_input(self, name: str) -> None:
        encoded = str(name).encode("latin-1", errors="ignore")[:PLAYER_NAME_MAX_BYTES]
        buf = bytearray(PLAYER_NAME_SIZE)
        buf[: len(encoded)] = encoded
        buf[min(len(encoded), PLAYER_NAME_MAX_BYTES)] = 0

        end = buf.index(0)
        i = end - 1
        while i > 0 and buf[i] == 0x20:
            buf[i] = 0
            i -= 1

        self.player_name = bytes(buf).split(b"\x00", 1)[0].decode("latin-1", errors="ignore")
        self.player_name_input_len = len(encoded)

    def saved_name_labels(self) -> tuple[str, ...]:
        count = _clamp(self.saved_name_count, minimum=1, maximum=SAVED_NAME_SLOT_COUNT)
        labels: list[str] = []
        for idx in range(count):
            label = str(self.saved_names[idx]).strip()
            if not label:
                label = "default" if idx == 0 else f"slot_{idx}"
            labels.append(label)
        return tuple(labels)


class CrimsonPlayerControls(msgspec.Struct):
    movement: MovementControlType
    aim_scheme: AimScheme
    keybinds: PlayerKeybindBlock
    show_direction_arrow: bool

    def keybind(self, slot_index: int) -> int:
        slot = int(slot_index)
        if slot < 0 or slot >= PLAYER_BIND_BLOCK_DWORDS:
            return KEYBIND_UNBOUND_CODE
        return int(self.keybinds[slot])

    def set_keybind(self, slot_index: int, value: int) -> None:
        slot = int(slot_index)
        if slot < 0 or slot >= PLAYER_BIND_BLOCK_DWORDS:
            return
        block = list(self.keybinds)
        while len(block) < PLAYER_BIND_BLOCK_DWORDS:
            block.append(KEYBIND_UNBOUND_CODE)
        block[slot] = int(value) & 0xFFFFFFFF
        self.keybinds = _bind_block_tuple(block)


class CrimsonControlsConfig(msgspec.Struct):
    players: tuple[CrimsonPlayerControls, CrimsonPlayerControls, CrimsonPlayerControls, CrimsonPlayerControls]
    pick_perk_key: int
    reload_key: int

    def player(self, player_index: int) -> CrimsonPlayerControls:
        return self.players[_clamp(player_index, minimum=0, maximum=3)]


class CrimsonConfig(msgspec.Struct):
    path: Path
    display: CrimsonDisplayConfig
    audio: CrimsonAudioConfig
    gameplay: CrimsonGameplayConfig
    profile: CrimsonProfileConfig
    controls: CrimsonControlsConfig

    def save(self) -> None:
        self.path.write_bytes(encode_crimson_cfg(self))


def _clamp(value: int, *, minimum: int, maximum: int) -> int:
    return max(minimum, min(maximum, int(value)))


def _as_int(value: object, *, default: int = 0) -> int:
    if value is None:
        return int(default)
    return int(cast(Any, value))


def _as_float(value: object, *, default: float = 0.0) -> float:
    if value is None:
        return float(default)
    return float(cast(Any, value))


def _u32(value: object) -> int:
    return _as_int(value) & 0xFFFFFFFF


def _u8(value: object) -> int:
    return _as_int(value) & 0xFF


def _bool_from_raw(value: object, *, default: bool = False) -> bool:
    return _as_int(value, default=1 if default else 0) != 0


def _float_from_raw(value: object, *, default: float) -> float:
    return _as_float(value, default=default)


def _coerce_u32_sequence(raw: object, *, count: int) -> tuple[int, ...]:
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes, bytearray)):
        return tuple(0 for _ in range(count))
    values = [0] * count
    for idx in range(min(len(raw), count)):
        values[idx] = _u32(raw[idx])
    return tuple(values)


def _coerce_u8_sequence(raw: object, *, count: int, fill: int = 0) -> tuple[int, ...]:
    values = [_u8(fill)] * count
    if isinstance(raw, (bytes, bytearray)):
        seq: Sequence[int] = raw
    elif isinstance(raw, Sequence) and not isinstance(raw, str):
        seq = raw
    else:
        return tuple(values)
    for idx in range(min(len(seq), count)):
        values[idx] = _u8(seq[idx])
    return tuple(values)


def _coerce_keybind_blob(raw: object) -> bytearray:
    if not isinstance(raw, (bytes, bytearray)):
        return bytearray(KEYBINDS_BLOB_SIZE)
    blob = bytearray(raw)
    if len(blob) < KEYBINDS_BLOB_SIZE:
        blob.extend(b"\x00" * (KEYBINDS_BLOB_SIZE - len(blob)))
    if len(blob) > KEYBINDS_BLOB_SIZE:
        del blob[KEYBINDS_BLOB_SIZE:]
    return blob


def _read_dword_block(blob: bytes | bytearray, *, offset: int) -> tuple[int, ...]:
    values: list[int] = []
    for idx in range(PLAYER_BIND_BLOCK_DWORDS):
        start = int(offset) + idx * 4
        values.append(int.from_bytes(blob[start : start + 4], "little"))
    return tuple(values)


def _block_uninitialized(values: Sequence[int]) -> bool:
    for idx in range(min(len(values), PLAYER_BIND_INPUT_DWORDS)):
        if int(values[idx]) != 0:
            return False
    return True


def _bind_block_tuple(values: Sequence[int], *, default_values: Sequence[int] | None = None) -> PlayerKeybindBlock:
    defaults = list(default_values if default_values is not None else _default_player_bind_block(0))
    while len(defaults) < PLAYER_BIND_BLOCK_DWORDS:
        defaults.append(KEYBIND_UNBOUND_CODE)
    block = defaults[:PLAYER_BIND_BLOCK_DWORDS]
    for idx in range(min(len(values), PLAYER_BIND_BLOCK_DWORDS)):
        block[idx] = _u32(values[idx])
    return cast(
        PlayerKeybindBlock,
        tuple(_u32(value) for value in block[:PLAYER_BIND_BLOCK_DWORDS]),
    )


def _decode_player_bind_block(raw: dict, *, player_index: int) -> PlayerKeybindBlock:
    idx = _clamp(player_index, minimum=0, maximum=3)
    if idx < 2:
        blob = _coerce_keybind_blob(raw.get("keybinds"))
        block = _read_dword_block(blob, offset=idx * PLAYER_BIND_BLOCK_SIZE)
    else:
        field = "extended_keybinds_p3" if idx == 2 else "extended_keybinds_p4"
        block = _coerce_u32_sequence(raw.get(field), count=PLAYER_BIND_BLOCK_DWORDS)
    if _block_uninitialized(block):
        return _default_player_bind_block(idx)
    return _bind_block_tuple(block)


def _encode_keybind_blob(players: Sequence[CrimsonPlayerControls]) -> bytes:
    blob = bytearray(KEYBINDS_BLOB_SIZE)
    for idx in range(2):
        values = _bind_block_tuple(players[idx].keybinds, default_values=_default_player_bind_block(idx))
        for slot, value in enumerate(values):
            start = idx * PLAYER_BIND_BLOCK_SIZE + slot * 4
            blob[start : start + 4] = _u32(value).to_bytes(4, "little")
    return bytes(blob)


def _decode_direction_arrow(raw: dict, *, player_index: int) -> bool:
    idx = int(player_index)
    if idx < 0:
        return False
    if idx < 2:
        values = raw.get("direction_arrow_flags", b"\x01\x01")
        if not isinstance(values, (bytes, bytearray)):
            return True
        if idx >= len(values):
            return True
        return bool(values[idx])

    flags = _coerce_u8_sequence(
        raw.get("extended_direction_arrow_flags"),
        count=EXT_DIRECTION_ARROW_FLAG_COUNT,
        fill=EXT_DIRECTION_ARROW_UNSET,
    )
    if idx > 3:
        return True
    value = int(flags[idx - 2])
    if value == EXT_DIRECTION_ARROW_OFF:
        return False
    if value == EXT_DIRECTION_ARROW_ON:
        return True
    return True


def _encode_direction_arrow_flags(players: Sequence[CrimsonPlayerControls]) -> tuple[bytes, tuple[int, int]]:
    primary = bytearray(b"\x01\x01")
    for idx in range(2):
        primary[idx] = 1 if bool(players[idx].show_direction_arrow) else 0
    extended: list[int] = []
    for idx in range(2, 4):
        extended.append(EXT_DIRECTION_ARROW_ON if bool(players[idx].show_direction_arrow) else EXT_DIRECTION_ARROW_OFF)
    return bytes(primary), (extended[0], extended[1])


def _decode_movement(value: object) -> MovementControlType:
    raw = _as_int(value, default=0)
    if raw <= 0:
        return MovementControlType.STATIC
    return movement_control_type_from_value(raw)


def _decode_aim_scheme(value: object) -> AimScheme:
    scheme = aim_scheme_from_value(_as_int(value, default=0))
    if scheme is AimScheme.UNKNOWN:
        return AimScheme.MOUSE
    return scheme


def _decode_game_mode(value: object) -> GameMode:
    try:
        return GameMode(_as_int(value, default=0))
    except (TypeError, ValueError):
        return GameMode.DEMO


def _decode_quest_level(major: object, minor: object) -> QuestLevel | None:
    major_value = _as_int(major, default=0)
    minor_value = _as_int(minor, default=0)
    if major_value <= 0 or minor_value <= 0:
        return None
    try:
        return QuestLevel(major=major_value, minor=minor_value)
    except msgspec.ValidationError:
        return None


def _decode_high_score_date_mode(value: object) -> HighScoreDateMode:
    raw = _clamp(_as_int(value, default=0), minimum=0, maximum=3)
    return HighScoreDateMode(raw)


def _decode_player_name(raw: object) -> str:
    if not isinstance(raw, (bytes, bytearray)):
        return ""
    return bytes(raw).split(b"\x00", 1)[0].decode("latin-1", errors="ignore")


def _encode_player_name_buffer(name: str) -> bytes:
    encoded = str(name).encode("latin-1", errors="ignore")[:PLAYER_NAME_MAX_BYTES]
    buf = bytearray(PLAYER_NAME_SIZE)
    buf[: len(encoded)] = encoded
    buf[min(len(encoded), PLAYER_NAME_MAX_BYTES)] = 0
    return bytes(buf)


def _decode_saved_names(raw: object) -> tuple[str, str, str, str, str, str, str, str]:
    blob = bytes(raw) if isinstance(raw, (bytes, bytearray)) else (b"\x00" * SAVED_NAMES_BLOB_SIZE)
    if len(blob) < SAVED_NAMES_BLOB_SIZE:
        blob = blob.ljust(SAVED_NAMES_BLOB_SIZE, b"\x00")
    if len(blob) > SAVED_NAMES_BLOB_SIZE:
        blob = blob[:SAVED_NAMES_BLOB_SIZE]
    names: list[str] = []
    for idx in range(SAVED_NAME_SLOT_COUNT):
        entry = blob[idx * SAVED_NAME_ENTRY_SIZE : (idx + 1) * SAVED_NAME_ENTRY_SIZE]
        names.append(entry.split(b"\x00", 1)[0].decode("latin-1", errors="ignore"))
    return tuple(names)  # type: ignore[return-value]


def _encode_saved_names_blob(names: Sequence[str]) -> bytes:
    out = bytearray(SAVED_NAMES_BLOB_SIZE)
    for idx in range(SAVED_NAME_SLOT_COUNT):
        name = str(names[idx]) if idx < len(names) else ""
        encoded = name.encode("latin-1", errors="ignore")[: SAVED_NAME_ENTRY_SIZE - 1]
        start = idx * SAVED_NAME_ENTRY_SIZE
        out[start : start + SAVED_NAME_ENTRY_SIZE] = b"\x00" * SAVED_NAME_ENTRY_SIZE
        out[start : start + len(encoded)] = encoded
        out[start + min(len(encoded), SAVED_NAME_ENTRY_SIZE - 1)] = 0
    return bytes(out)


def _saved_name_order_blob() -> bytes:
    blob = bytearray()
    for idx in range(SAVED_NAME_SLOT_COUNT):
        blob += int(idx).to_bytes(4, "little")
    return bytes(blob)


def _default_player_bind_block(player_index: int) -> PlayerKeybindBlock:
    idx = _clamp(player_index, minimum=0, maximum=len(_DEFAULT_PLAYER_BIND_BLOCKS) - 1)
    return cast(PlayerKeybindBlock, _DEFAULT_PLAYER_BIND_BLOCKS[idx])


def default_player_keybind_block(player_index: int) -> tuple[int, ...]:
    return _default_player_bind_block(player_index)


def _default_player_controls(player_index: int) -> CrimsonPlayerControls:
    return CrimsonPlayerControls(
        movement=MovementControlType.STATIC,
        aim_scheme=AimScheme.MOUSE,
        keybinds=_bind_block_tuple(_default_player_bind_block(player_index)),
        show_direction_arrow=True,
    )


def default_crimson_cfg(path: Path = Path("<memory>")) -> CrimsonConfig:
    profile = CrimsonProfileConfig(
        player_name="",
        player_name_input_len=0,
        saved_name_count=1,
        selected_saved_name_slot=0,
        saved_names=_DEFAULT_SAVED_NAMES,
        show_internet_scores=False,
        score_date_mode=HighScoreDateMode.ALL_TIME,
    )
    profile.set_player_name_input(_DEFAULT_PROFILE_NAME)
    profile.player_name_input_len = 0
    return CrimsonConfig(
        path=path,
        display=CrimsonDisplayConfig(
            width=1024,
            height=768,
            windowed=True,
            bpp=32,
            texture_scale=1.0,
            mouse_sensitivity=1.0,
            detail_preset=5,
            fx_detail=(True, True, True),
            gore_disabled=0,
        ),
        audio=CrimsonAudioConfig(
            sound_disabled=False,
            music_disabled=False,
            sfx_volume=1.0,
            music_volume=1.0,
        ),
        gameplay=CrimsonGameplayConfig(
            mode=GameMode.SURVIVAL,
            player_count=1,
            hardcore=False,
            quest_level=None,
            show_info_texts=True,
        ),
        profile=profile,
        controls=CrimsonControlsConfig(
            players=(
                _default_player_controls(0),
                _default_player_controls(1),
                _default_player_controls(2),
                _default_player_controls(3),
            ),
            pick_perk_key=0x101,
            reload_key=0x102,
        ),
    )


def decode_crimson_cfg(path: Path, blob: bytes) -> CrimsonConfig:
    if len(blob) != CRIMSON_CFG_SIZE:
        raise ValueError(f"{path} has unexpected size {len(blob)} (expected {CRIMSON_CFG_SIZE})")
    raw = CRIMSON_CFG_STRUCT.parse(blob)

    fx_detail = (
        _bool_from_raw(raw.get("fx_detail_0")),
        _bool_from_raw(raw.get("fx_detail_1")),
        _bool_from_raw(raw.get("fx_detail_2")),
    )
    detail_preset = _as_int(raw.get("detail_preset"), default=5)
    if detail_preset == 0 and not any(fx_detail):
        detail_preset = 5
        fx_detail = (True, True, True)

    players = tuple(
        CrimsonPlayerControls(
            movement=_decode_movement(raw.get(f"player_mode_flag_p{idx + 1}")),
            aim_scheme=_decode_aim_scheme(raw.get(f"aim_scheme_p{idx + 1}")),
            keybinds=_bind_block_tuple(_decode_player_bind_block(raw, player_index=idx)),
            show_direction_arrow=_decode_direction_arrow(raw, player_index=idx),
        )
        for idx in range(4)
    )

    return CrimsonConfig(
        path=path,
        display=CrimsonDisplayConfig(
            width=_as_int(raw.get("screen_width"), default=1024),
            height=_as_int(raw.get("screen_height"), default=768),
            windowed=_bool_from_raw(raw.get("windowed_flag"), default=True),
            bpp=_as_int(raw.get("screen_bpp"), default=32),
            texture_scale=_float_from_raw(raw.get("texture_scale"), default=1.0),
            mouse_sensitivity=_float_from_raw(raw.get("mouse_sensitivity"), default=1.0),
            detail_preset=_clamp(detail_preset, minimum=1, maximum=5),
            fx_detail=fx_detail,
            gore_disabled=_as_int(raw.get("gore_disabled"), default=0),
        ),
        audio=CrimsonAudioConfig(
            sound_disabled=_bool_from_raw(raw.get("sound_disable"), default=False),
            music_disabled=_bool_from_raw(raw.get("music_disable"), default=False),
            sfx_volume=_float_from_raw(raw.get("sfx_volume"), default=1.0),
            music_volume=_float_from_raw(raw.get("music_volume"), default=1.0),
        ),
        gameplay=CrimsonGameplayConfig(
            mode=_decode_game_mode(raw.get("game_mode")),
            player_count=_clamp(_as_int(raw.get("player_count"), default=1), minimum=1, maximum=4),
            hardcore=_bool_from_raw(raw.get("hardcore_flag"), default=False),
            quest_level=_decode_quest_level(raw.get("quest_stage_major"), raw.get("quest_stage_minor")),
            show_info_texts=_bool_from_raw(raw.get("ui_info_texts"), default=True),
        ),
        profile=CrimsonProfileConfig(
            player_name=_decode_player_name(raw.get("player_name")),
            player_name_input_len=_clamp(
                _as_int(raw.get("player_name_len"), default=0),
                minimum=0,
                maximum=PLAYER_NAME_MAX_BYTES,
            ),
            saved_name_count=_clamp(
                _as_int(raw.get("saved_name_index"), default=1),
                minimum=1,
                maximum=SAVED_NAME_SLOT_COUNT,
            ),
            selected_saved_name_slot=_clamp(
                _as_int(raw.get("selected_name_slot"), default=0),
                minimum=0,
                maximum=SAVED_NAME_SLOT_COUNT - 1,
            ),
            saved_names=_decode_saved_names(raw.get("saved_names")),
            show_internet_scores=_bool_from_raw(raw.get("score_load_gate"), default=False),
            score_date_mode=_decode_high_score_date_mode(raw.get("highscore_date_mode")),
        ),
        controls=CrimsonControlsConfig(
            players=players,  # type: ignore[arg-type]
            pick_perk_key=_as_int(raw.get("keybind_pick_perk"), default=0x101) or 0x101,
            reload_key=_as_int(raw.get("keybind_reload"), default=0x102) or 0x102,
        ),
    )


def _canonical_wire_data() -> dict:
    return dict(CRIMSON_CFG_STRUCT.parse(bytes(CRIMSON_CFG_SIZE)))


def encode_crimson_cfg(config: CrimsonConfig) -> bytes:
    data = _canonical_wire_data()
    primary_direction_arrows, extended_direction_arrows = _encode_direction_arrow_flags(config.controls.players)

    data["sound_disable"] = 1 if config.audio.sound_disabled else 0
    data["music_disable"] = 1 if config.audio.music_disabled else 0
    data["highscore_date_mode"] = int(config.profile.score_date_mode)
    data["direction_arrow_flags"] = primary_direction_arrows
    data["unknown_08"] = 8
    data["fx_detail_0"] = 1 if config.display.fx_detail_enabled(0) else 0
    data["fx_detail_1"] = 1 if config.display.fx_detail_enabled(1) else 0
    data["fx_detail_2"] = 1 if config.display.fx_detail_enabled(2) else 0
    data["player_count"] = _clamp(config.gameplay.player_count, minimum=1, maximum=4)
    data["game_mode"] = int(config.gameplay.mode)
    for idx in range(4):
        player = config.controls.player(idx)
        data[f"player_mode_flag_p{idx + 1}"] = int(player.movement)
        data[f"aim_scheme_p{idx + 1}"] = int(player.aim_scheme)
    data["texture_scale"] = float(config.display.texture_scale)
    data["selected_name_slot"] = _clamp(
        config.profile.selected_saved_name_slot,
        minimum=0,
        maximum=SAVED_NAME_SLOT_COUNT - 1,
    )
    data["saved_name_index"] = _clamp(config.profile.saved_name_count, minimum=1, maximum=SAVED_NAME_SLOT_COUNT)
    data["saved_name_order"] = _saved_name_order_blob()
    data["saved_names"] = _encode_saved_names_blob(config.profile.saved_names)
    data["player_name"] = _encode_player_name_buffer(config.profile.player_name)
    data["player_name_len"] = _clamp(config.profile.player_name_input_len, minimum=0, maximum=PLAYER_NAME_MAX_BYTES)
    data["unknown_1a4"] = 100
    data["aim_pov_right"] = 9000
    data["aim_pov_left"] = 27000
    data["screen_bpp"] = _u32(config.display.bpp)
    data["screen_width"] = _u32(config.display.width)
    data["screen_height"] = _u32(config.display.height)
    data["windowed_flag"] = 1 if config.display.windowed else 0
    data["keybinds"] = _encode_keybind_blob(config.controls.players)
    data["extended_keybinds_p3"] = list(
        _bind_block_tuple(
            config.controls.player(2).keybinds,
            default_values=_default_player_bind_block(2),
        ),
    )
    data["extended_keybinds_p4"] = list(
        _bind_block_tuple(
            config.controls.player(3).keybinds,
            default_values=_default_player_bind_block(3),
        ),
    )
    data["extended_direction_arrow_flags"] = [int(extended_direction_arrows[0]), int(extended_direction_arrows[1])]
    data["hardcore_flag"] = 1 if config.gameplay.hardcore else 0
    data["ui_info_texts"] = 1 if config.gameplay.show_info_texts else 0
    data["sfx_volume"] = float(config.audio.sfx_volume)
    data["music_volume"] = float(config.audio.music_volume)
    data["gore_disabled"] = _u8(config.display.gore_disabled)
    data["score_load_gate"] = 1 if config.profile.show_internet_scores else 0
    data["detail_preset"] = _clamp(config.display.detail_preset, minimum=1, maximum=5)
    data["mouse_sensitivity"] = float(config.display.mouse_sensitivity)
    data["keybind_pick_perk"] = _u32(config.controls.pick_perk_key or 0x101)
    data["keybind_reload"] = _u32(config.controls.reload_key or 0x102)
    return CRIMSON_CFG_STRUCT.build(data)


def load_crimson_cfg(path: Path) -> CrimsonConfig:
    return decode_crimson_cfg(path, path.read_bytes())


def ensure_crimson_cfg(base_dir: Path) -> CrimsonConfig:
    path = base_dir / CRIMSON_CFG_NAME
    if not path.exists():
        config = default_crimson_cfg(path)
        config.save()
        return config
    raw = path.read_bytes()
    config = decode_crimson_cfg(path, raw)
    canonical = encode_crimson_cfg(config)
    if canonical != raw:
        path.write_bytes(canonical)
    return config


def apply_detail_preset(config: CrimsonConfig, preset: int | None = None) -> int:
    selected = config.display.detail_preset if preset is None else int(preset)
    selected = _clamp(selected, minimum=1, maximum=5)
    config.display.detail_preset = selected
    if selected <= 1:
        config.display.fx_detail = (False, False, False)
    elif selected == 2:
        config.display.fx_detail = (False, False, True)
    else:
        config.display.fx_detail = (True, True, True)
    return selected
