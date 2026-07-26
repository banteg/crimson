from __future__ import annotations

from collections.abc import Sequence
from enum import IntEnum
from pathlib import Path
from typing import Any, cast

import msgspec
from construct import Array, Byte, Bytes, Float32l, Int32sl, Struct

from crimson.aim_schemes import AimScheme
from crimson.game_modes import GameMode
from crimson.movement_controls import MovementControlType
from crimson.quests.level import QuestLevel

CRIMSON_CFG_NAME = "crimson.cfg"
CRIMSON_CFG_SIZE = 0x480
PLAYER_NAME_SIZE = 0x20
PLAYER_NAME_MAX_BYTES = PLAYER_NAME_SIZE - 1
SAVED_NAME_SLOT_COUNT = 8
SAVED_NAME_ENTRY_SIZE = 0x1B
SAVED_NAMES_BLOB_SIZE = SAVED_NAME_SLOT_COUNT * SAVED_NAME_ENTRY_SIZE
UNKNOWN_248_SIZE = 0x1F8
PLAYER_BIND_BLOCK_DWORDS = 0x10
PLAYER_BIND_BLOCK_SIZE = PLAYER_BIND_BLOCK_DWORDS * 4
EXT_DIRECTION_ARROW_FLAG_COUNT = 2
EXTENDED_RESERVED_GAP_SIZE = UNKNOWN_248_SIZE - 2 * PLAYER_BIND_BLOCK_SIZE - EXT_DIRECTION_ARROW_FLAG_COUNT
EXT_DIRECTION_ARROW_UNSET = 0
EXT_DIRECTION_ARROW_OFF = 1
EXT_DIRECTION_ARROW_ON = 2
KEYBIND_UNBOUND_CODE = 0x17E
RESERVED_KEYBIND_SLOT_COUNT = 2
PADDING_KEYBIND_SLOT_COUNT = 3
_DEFAULT_WIRE_RESERVED_KEYS = (KEYBIND_UNBOUND_CODE, KEYBIND_UNBOUND_CODE)
_DEFAULT_WIRE_PADDING = (KEYBIND_UNBOUND_CODE, KEYBIND_UNBOUND_CODE, KEYBIND_UNBOUND_CODE)

PLAYER_BIND_BLOCK_STRUCT = Struct(
    "move_forward" / Int32sl,
    "move_backward" / Int32sl,
    "turn_left" / Int32sl,
    "turn_right" / Int32sl,
    "fire" / Int32sl,
    "reserved_keys" / Array(RESERVED_KEYBIND_SLOT_COUNT, Int32sl),
    "aim_left" / Int32sl,
    "aim_right" / Int32sl,
    "axis_aim_y" / Int32sl,
    "axis_aim_x" / Int32sl,
    "axis_move_y" / Int32sl,
    "axis_move_x" / Int32sl,
    "padding" / Array(PADDING_KEYBIND_SLOT_COUNT, Int32sl),
)

CRIMSON_CFG_STRUCT = Struct(
    "sound_disable" / Byte,
    "music_disable" / Byte,
    "highscore_date_mode" / Byte,
    "highscore_duplicate_mode" / Byte,
    "direction_arrow_flags" / Array(2, Byte),
    "unknown_06" / Bytes(2),
    "unknown_08" / Int32sl,
    "unknown_0c" / Bytes(2),
    "fx_detail_0" / Byte,
    "unknown_0f" / Byte,
    "fx_detail_1" / Byte,
    "fx_detail_2" / Byte,
    "unknown_12" / Bytes(2),
    "player_count" / Int32sl,
    "game_mode" / Int32sl,
    "player_mode_flags" / Array(4, Int32sl),
    "player_mode_flags_reserved" / Bytes(0x18),
    "aim_schemes" / Array(4, Int32sl),
    "aim_schemes_reserved" / Bytes(0x18),
    "unknown_6c" / Int32sl,
    "texture_scale" / Float32l,
    "player_name_buf" / Bytes(12),
    "selected_saved_name_slot" / Int32sl,
    "saved_name_count" / Int32sl,
    "saved_name_order" / Array(SAVED_NAME_SLOT_COUNT, Int32sl),
    "saved_names" / Bytes(SAVED_NAMES_BLOB_SIZE),
    "player_name" / Bytes(PLAYER_NAME_SIZE),
    "player_name_len" / Int32sl,
    "unknown_1a4" / Int32sl,
    "unknown_1a8" / Int32sl,
    "unknown_1ac" / Int32sl,
    "aim_pov_right" / Int32sl,
    "aim_pov_left" / Int32sl,
    "screen_bpp" / Int32sl,
    "screen_width" / Int32sl,
    "screen_height" / Int32sl,
    "windowed_flag" / Byte,
    "unknown_1c5" / Bytes(3),
    "keybinds_p1_p2" / Array(2, PLAYER_BIND_BLOCK_STRUCT),
    # The original wire format leaves this 0x1F8-byte gap uninterpreted.
    # The Python port uses the front of it for P3/P4 control bindings and
    # their direction-arrow flags, while preserving the remaining bytes.
    "extended_keybinds_p3_p4" / Array(2, PLAYER_BIND_BLOCK_STRUCT),
    "extended_direction_arrow_flags" / Array(EXT_DIRECTION_ARROW_FLAG_COUNT, Byte),
    "extended_reserved_gap" / Bytes(EXTENDED_RESERVED_GAP_SIZE),
    "unknown_440" / Int32sl,
    "unknown_444" / Int32sl,
    "hardcore_flag" / Byte,
    "ui_info_texts" / Byte,
    "unknown_44a" / Bytes(2),
    "perk_prompt_counter" / Int32sl,
    "unknown_450" / Int32sl,
    "unknown_454" / Bytes(0x0C),
    "sound_freq_adjustment_enabled" / Byte,
    "unknown_461" / Bytes(3),
    "sfx_volume" / Float32l,
    "music_volume" / Float32l,
    "violence_disabled" / Byte,
    "score_load_gate" / Byte,
    "safe_mode_backend_enabled" / Byte,
    "unknown_46f" / Byte,
    "detail_preset" / Int32sl,
    "mouse_sensitivity" / Float32l,
    "keybind_pick_perk" / Int32sl,
    "keybind_reload" / Int32sl,
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
    violence_disabled: int

    def fx_detail_enabled(self, level: int, default: bool = False) -> bool:
        _ = default
        return bool(self.fx_detail[int(level)])

    def set_fx_detail(self, level: int, enabled: bool) -> None:
        idx = int(level)
        values = list(self.fx_detail)
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
        count = int(self.saved_name_count)
        if count < 1 or count > SAVED_NAME_SLOT_COUNT:
            raise ValueError(f"saved_name_count must be in 1..{SAVED_NAME_SLOT_COUNT}, got {count}")
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
    show_direction_arrow: bool
    move_codes: tuple[int, int, int, int]
    fire_code: int
    keyboard_aim_codes: tuple[int, int]
    aim_axis_codes: tuple[int, int]
    move_axis_codes: tuple[int, int]


_DEFAULT_PLAYER_CONTROL_TEMPLATES: tuple[CrimsonPlayerControls, ...] = (
    CrimsonPlayerControls(
        movement=MovementControlType.STATIC,
        aim_scheme=AimScheme.MOUSE,
        show_direction_arrow=True,
        move_codes=(0x11, 0x1F, 0x1E, 0x20),
        fire_code=0x100,
        keyboard_aim_codes=(0x10, 0x12),
        aim_axis_codes=(0x13F, 0x140),
        move_axis_codes=(0x141, 0x153),
    ),
    CrimsonPlayerControls(
        movement=MovementControlType.STATIC,
        aim_scheme=AimScheme.MOUSE,
        show_direction_arrow=True,
        move_codes=(0xC8, 0xD0, 0xCB, 0xCD),
        fire_code=0x9D,
        keyboard_aim_codes=(0xD3, 0xD1),
        aim_axis_codes=(0x13F, 0x140),
        move_axis_codes=(0x141, 0x153),
    ),
    CrimsonPlayerControls(
        movement=MovementControlType.STATIC,
        aim_scheme=AimScheme.MOUSE,
        show_direction_arrow=True,
        move_codes=(0x17, 0x25, 0x24, 0x26),
        fire_code=0x36,
        keyboard_aim_codes=(0x16, 0x18),
        aim_axis_codes=(0x17E, 0x17E),
        move_axis_codes=(0x17E, 0x17E),
    ),
    CrimsonPlayerControls(
        movement=MovementControlType.STATIC,
        aim_scheme=AimScheme.MOUSE,
        show_direction_arrow=True,
        move_codes=(0x131, 0x132, 0x133, 0x134),
        fire_code=0x11F,
        keyboard_aim_codes=(0x17E, 0x17E),
        aim_axis_codes=(0x140, 0x13F),
        move_axis_codes=(0x153, 0x154),
    ),
)


class CrimsonControlsConfig(msgspec.Struct):
    players: tuple[CrimsonPlayerControls, CrimsonPlayerControls, CrimsonPlayerControls, CrimsonPlayerControls]
    pick_perk_code: int
    reload_code: int

    def player(self, player_index: int) -> CrimsonPlayerControls:
        return self.players[_player_index(player_index)]


class CrimsonConfig(msgspec.Struct):
    path: Path
    display: CrimsonDisplayConfig
    audio: CrimsonAudioConfig
    gameplay: CrimsonGameplayConfig
    profile: CrimsonProfileConfig
    controls: CrimsonControlsConfig

    def save(self) -> None:
        self.path.write_bytes(encode_crimson_cfg(self))


def _player_index(player_index: int) -> int:
    idx = int(player_index)
    if idx < 0 or idx >= 4:
        raise IndexError(f"player index must be in 0..3, got {idx}")
    return idx


def _require_range(value: int, *, minimum: int, maximum: int, field: str) -> int:
    if value < minimum or value > maximum:
        raise ValueError(f"{field} must be in {minimum}..{maximum}, got {value}")
    return value


def _parsed_player_bind_block(raw: dict[str, Any], *, player_index: int) -> dict[str, Any]:
    idx = _player_index(player_index)
    if idx < 2:
        return raw["keybinds_p1_p2"][idx]
    return raw["extended_keybinds_p3_p4"][idx - 2]


def _parsed_player_bind_block_is_uninitialized(raw_block: dict[str, Any]) -> bool:
    return not any(
        (
            raw_block["move_forward"],
            raw_block["move_backward"],
            raw_block["turn_left"],
            raw_block["turn_right"],
            raw_block["fire"],
            *raw_block["reserved_keys"],
            raw_block["aim_left"],
            raw_block["aim_right"],
            raw_block["axis_aim_y"],
            raw_block["axis_aim_x"],
            raw_block["axis_move_y"],
            raw_block["axis_move_x"],
        ),
    )


def _player_controls_from_parsed_bind_block(
    raw_block: dict[str, Any],
    *,
    player_index: int,
    movement: MovementControlType,
    aim_scheme: AimScheme,
    show_direction_arrow: bool,
) -> CrimsonPlayerControls:
    if _parsed_player_bind_block_is_uninitialized(raw_block):
        defaults = _default_player_controls(player_index)
        return CrimsonPlayerControls(
            movement=movement,
            aim_scheme=aim_scheme,
            show_direction_arrow=show_direction_arrow,
            move_codes=defaults.move_codes,
            fire_code=defaults.fire_code,
            keyboard_aim_codes=defaults.keyboard_aim_codes,
            aim_axis_codes=defaults.aim_axis_codes,
            move_axis_codes=defaults.move_axis_codes,
        )
    return CrimsonPlayerControls(
        movement=movement,
        aim_scheme=aim_scheme,
        show_direction_arrow=show_direction_arrow,
        move_codes=(
            raw_block["move_forward"],
            raw_block["move_backward"],
            raw_block["turn_left"],
            raw_block["turn_right"],
        ),
        fire_code=raw_block["fire"],
        keyboard_aim_codes=(raw_block["aim_left"], raw_block["aim_right"]),
        aim_axis_codes=(raw_block["axis_aim_y"], raw_block["axis_aim_x"]),
        move_axis_codes=(raw_block["axis_move_y"], raw_block["axis_move_x"]),
    )


def _encode_player_bind_block(player: CrimsonPlayerControls) -> dict[str, object]:
    return {
        "move_forward": player.move_codes[0],
        "move_backward": player.move_codes[1],
        "turn_left": player.move_codes[2],
        "turn_right": player.move_codes[3],
        "fire": player.fire_code,
        "reserved_keys": [int(_DEFAULT_WIRE_RESERVED_KEYS[0]), int(_DEFAULT_WIRE_RESERVED_KEYS[1])],
        "aim_left": player.keyboard_aim_codes[0],
        "aim_right": player.keyboard_aim_codes[1],
        "axis_aim_y": player.aim_axis_codes[0],
        "axis_aim_x": player.aim_axis_codes[1],
        "axis_move_y": player.move_axis_codes[0],
        "axis_move_x": player.move_axis_codes[1],
        "padding": [int(_DEFAULT_WIRE_PADDING[0]), int(_DEFAULT_WIRE_PADDING[1]), int(_DEFAULT_WIRE_PADDING[2])],
    }


def _encode_primary_keybinds(players: Sequence[CrimsonPlayerControls]) -> list[dict[str, object]]:
    return [_encode_player_bind_block(players[idx]) for idx in range(2)]


def _encode_extended_keybinds(players: Sequence[CrimsonPlayerControls]) -> list[dict[str, object]]:
    return [_encode_player_bind_block(players[idx]) for idx in range(2, 4)]


def _decode_direction_arrow(raw: dict, *, player_index: int) -> bool:
    idx = _player_index(player_index)
    if idx < 2:
        return bool(int(raw["direction_arrow_flags"][idx]))

    value = int(raw["extended_direction_arrow_flags"][idx - 2])
    if value == EXT_DIRECTION_ARROW_OFF:
        return False
    if value in (EXT_DIRECTION_ARROW_UNSET, EXT_DIRECTION_ARROW_ON):
        return True
    raise ValueError(f"unsupported extended direction arrow flag value: {value}")


def _encode_direction_arrow_flags(players: Sequence[CrimsonPlayerControls]) -> tuple[list[int], tuple[int, int]]:
    primary = [1, 1]
    for idx in range(2):
        primary[idx] = 1 if bool(players[idx].show_direction_arrow) else 0
    extended: list[int] = []
    for idx in range(2, 4):
        extended.append(EXT_DIRECTION_ARROW_ON if bool(players[idx].show_direction_arrow) else EXT_DIRECTION_ARROW_OFF)
    return primary, (extended[0], extended[1])


def _decode_movement(value: int) -> MovementControlType:
    raw = int(value)
    if raw == 0:
        return MovementControlType.STATIC
    return MovementControlType(raw)


def _decode_aim_scheme(value: int) -> AimScheme:
    return AimScheme(int(value))


def _decode_game_mode(value: int) -> GameMode:
    return GameMode(int(value))


def _decode_high_score_date_mode(value: int) -> HighScoreDateMode:
    return HighScoreDateMode(int(value))


def _decode_player_name(raw: bytes) -> str:
    return bytes(raw).split(b"\x00", 1)[0].decode("latin-1", errors="ignore")


def _encode_player_name_buffer(name: str) -> bytes:
    encoded = str(name).encode("latin-1", errors="ignore")[:PLAYER_NAME_MAX_BYTES]
    buf = bytearray(PLAYER_NAME_SIZE)
    buf[: len(encoded)] = encoded
    buf[min(len(encoded), PLAYER_NAME_MAX_BYTES)] = 0
    return bytes(buf)


def _decode_saved_names(raw: bytes) -> tuple[str, str, str, str, str, str, str, str]:
    blob = bytes(raw)
    names: list[str] = []
    for idx in range(SAVED_NAME_SLOT_COUNT):
        entry = blob[idx * SAVED_NAME_ENTRY_SIZE : (idx + 1) * SAVED_NAME_ENTRY_SIZE]
        names.append(entry.split(b"\x00", 1)[0].decode("latin-1", errors="ignore"))
    return cast("tuple[str, str, str, str, str, str, str, str]", tuple(names))


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


def _saved_name_order_values() -> tuple[int, ...]:
    return tuple(range(SAVED_NAME_SLOT_COUNT))


def _default_player_controls(player_index: int) -> CrimsonPlayerControls:
    defaults = _DEFAULT_PLAYER_CONTROL_TEMPLATES[_player_index(player_index)]
    return CrimsonPlayerControls(
        movement=defaults.movement,
        aim_scheme=defaults.aim_scheme,
        show_direction_arrow=defaults.show_direction_arrow,
        move_codes=defaults.move_codes,
        fire_code=defaults.fire_code,
        keyboard_aim_codes=defaults.keyboard_aim_codes,
        aim_axis_codes=defaults.aim_axis_codes,
        move_axis_codes=defaults.move_axis_codes,
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
            mouse_sensitivity=0.5,
            detail_preset=5,
            fx_detail=(True, True, True),
            violence_disabled=0,
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
            pick_perk_code=0x101,
            reload_code=0x102,
        ),
    )


def decode_crimson_cfg(path: Path, blob: bytes) -> CrimsonConfig:
    if len(blob) != CRIMSON_CFG_SIZE:
        raise ValueError(f"{path} has unexpected size {len(blob)} (expected {CRIMSON_CFG_SIZE})")
    raw = CRIMSON_CFG_STRUCT.parse(blob)

    fx_detail = (
        bool(raw["fx_detail_0"]),
        bool(raw["fx_detail_1"]),
        bool(raw["fx_detail_2"]),
    )
    detail_preset = int(raw["detail_preset"])
    if detail_preset == 0 and not any(fx_detail):
        detail_preset = 5
        fx_detail = (True, True, True)
    else:
        detail_preset = _require_range(detail_preset, minimum=1, maximum=5, field="detail_preset")

    players = tuple(
        _player_controls_from_parsed_bind_block(
            _parsed_player_bind_block(raw, player_index=idx),
            player_index=idx,
            movement=_decode_movement(raw["player_mode_flags"][idx]),
            aim_scheme=_decode_aim_scheme(raw["aim_schemes"][idx]),
            show_direction_arrow=_decode_direction_arrow(raw, player_index=idx),
        )
        for idx in range(4)
    )

    return CrimsonConfig(
        path=path,
        display=CrimsonDisplayConfig(
            width=int(raw["screen_width"]),
            height=int(raw["screen_height"]),
            windowed=bool(raw["windowed_flag"]),
            bpp=int(raw["screen_bpp"]),
            texture_scale=float(raw["texture_scale"]),
            mouse_sensitivity=float(raw["mouse_sensitivity"]),
            detail_preset=detail_preset,
            fx_detail=fx_detail,
            violence_disabled=int(raw["violence_disabled"]),
        ),
        audio=CrimsonAudioConfig(
            sound_disabled=bool(raw["sound_disable"]),
            music_disabled=bool(raw["music_disable"]),
            sfx_volume=float(raw["sfx_volume"]),
            music_volume=float(raw["music_volume"]),
        ),
        gameplay=CrimsonGameplayConfig(
            mode=_decode_game_mode(raw["game_mode"]),
            player_count=_require_range(int(raw["player_count"]), minimum=1, maximum=4, field="player_count"),
            hardcore=bool(raw["hardcore_flag"]),
            quest_level=None,
            show_info_texts=bool(raw["ui_info_texts"]),
        ),
        profile=CrimsonProfileConfig(
            player_name=_decode_player_name(raw["player_name"]),
            player_name_input_len=_require_range(
                int(raw["player_name_len"]),
                minimum=0,
                maximum=PLAYER_NAME_MAX_BYTES,
                field="player_name_len",
            ),
            saved_name_count=_require_range(
                int(raw["saved_name_count"]),
                minimum=1,
                maximum=SAVED_NAME_SLOT_COUNT,
                field="saved_name_count",
            ),
            selected_saved_name_slot=_require_range(
                int(raw["selected_saved_name_slot"]),
                minimum=0,
                maximum=SAVED_NAME_SLOT_COUNT - 1,
                field="selected_saved_name_slot",
            ),
            saved_names=_decode_saved_names(raw["saved_names"]),
            show_internet_scores=bool(raw["score_load_gate"]),
            score_date_mode=_decode_high_score_date_mode(raw["highscore_date_mode"]),
        ),
        controls=CrimsonControlsConfig(
            players=cast(
                "tuple[CrimsonPlayerControls, CrimsonPlayerControls, CrimsonPlayerControls, CrimsonPlayerControls]",
                players,
            ),
            pick_perk_code=int(raw["keybind_pick_perk"]),
            reload_code=int(raw["keybind_reload"]),
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
    data["unknown_08"] = 0
    data["fx_detail_0"] = 1 if config.display.fx_detail_enabled(0) else 0
    data["fx_detail_1"] = 1 if config.display.fx_detail_enabled(1) else 0
    data["fx_detail_2"] = 1 if config.display.fx_detail_enabled(2) else 0
    data["player_count"] = _require_range(
        int(config.gameplay.player_count),
        minimum=1,
        maximum=4,
        field="player_count",
    )
    data["game_mode"] = int(config.gameplay.mode)
    data["player_mode_flags"] = [int(player.movement) for player in config.controls.players]
    data["aim_schemes"] = [int(player.aim_scheme) for player in config.controls.players]
    data["texture_scale"] = float(config.display.texture_scale)
    data["selected_saved_name_slot"] = _require_range(
        int(config.profile.selected_saved_name_slot),
        minimum=0,
        maximum=SAVED_NAME_SLOT_COUNT - 1,
        field="selected_saved_name_slot",
    )
    data["saved_name_count"] = _require_range(
        int(config.profile.saved_name_count),
        minimum=1,
        maximum=SAVED_NAME_SLOT_COUNT,
        field="saved_name_count",
    )
    data["saved_name_order"] = list(_saved_name_order_values())
    data["saved_names"] = _encode_saved_names_blob(config.profile.saved_names)
    data["player_name"] = _encode_player_name_buffer(config.profile.player_name)
    data["player_name_len"] = _require_range(
        int(config.profile.player_name_input_len),
        minimum=0,
        maximum=PLAYER_NAME_MAX_BYTES,
        field="player_name_len",
    )
    data["unknown_1a4"] = 100
    data["aim_pov_right"] = 9000
    data["aim_pov_left"] = 27000
    data["screen_bpp"] = int(config.display.bpp)
    data["screen_width"] = int(config.display.width)
    data["screen_height"] = int(config.display.height)
    data["windowed_flag"] = 1 if config.display.windowed else 0
    data["keybinds_p1_p2"] = _encode_primary_keybinds(config.controls.players)
    data["extended_keybinds_p3_p4"] = _encode_extended_keybinds(config.controls.players)
    data["extended_direction_arrow_flags"] = [int(extended_direction_arrows[0]), int(extended_direction_arrows[1])]
    data["hardcore_flag"] = 1 if config.gameplay.hardcore else 0
    data["ui_info_texts"] = 1 if config.gameplay.show_info_texts else 0
    data["unknown_450"] = 1
    data["sound_freq_adjustment_enabled"] = 1
    data["sfx_volume"] = float(config.audio.sfx_volume)
    data["music_volume"] = float(config.audio.music_volume)
    data["violence_disabled"] = int(config.display.violence_disabled)
    data["score_load_gate"] = 1 if config.profile.show_internet_scores else 0
    data["detail_preset"] = _require_range(
        int(config.display.detail_preset),
        minimum=1,
        maximum=5,
        field="detail_preset",
    )
    data["mouse_sensitivity"] = float(config.display.mouse_sensitivity)
    data["keybind_pick_perk"] = config.controls.pick_perk_code
    data["keybind_reload"] = config.controls.reload_code
    return CRIMSON_CFG_STRUCT.build(data)


def load_crimson_cfg(path: Path) -> CrimsonConfig:
    return decode_crimson_cfg(path, path.read_bytes())


def ensure_crimson_cfg(base_dir: Path) -> CrimsonConfig:
    path = base_dir / CRIMSON_CFG_NAME
    if not path.exists():
        config = default_crimson_cfg(path)
        config.save()
        return config
    return load_crimson_cfg(path)


def apply_detail_preset(config: CrimsonConfig, preset: int | None = None) -> int:
    selected = config.display.detail_preset if preset is None else int(preset)
    selected = _require_range(selected, minimum=1, maximum=5, field="detail_preset")
    config.display.detail_preset = selected
    if selected <= 1:
        config.display.fx_detail = (False, False, False)
    elif selected == 2:
        config.display.fx_detail = (False, False, True)
    else:
        config.display.fx_detail = (True, True, True)
    return selected
