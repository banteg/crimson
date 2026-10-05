from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Sequence
from enum import IntEnum
from pathlib import Path
from typing import Any, NamedTuple, cast

import msgspec
from construct import Array, Byte, Bytes, Float32l, Int32sl, Struct

from crimson.aim_schemes import AimScheme
from crimson.game_modes import GameMode
from crimson.movement_controls import MovementControlType
from crimson.quests.level import QuestLevel

from .atomic_write import atomic_write_bytes

CRIMSON_CFG_NAME = "crimson.cfg"
CRIMSON_CFG_SIZE = 0x480
PLAYER_NAME_SIZE = 0x20
PLAYER_NAME_MAX_BYTES = PLAYER_NAME_SIZE - 1
SAVED_NAME_SLOT_COUNT = 8
SAVED_NAME_ENTRY_SIZE = 0x1B
SAVED_NAMES_BLOB_SIZE = SAVED_NAME_SLOT_COUNT * SAVED_NAME_ENTRY_SIZE
PLAYER_BIND_BLOCK_DWORDS = 0x10
PLAYER_BIND_BLOCK_SIZE = PLAYER_BIND_BLOCK_DWORDS * 4
CONFIG_PLAYER_SLOT_COUNT = 10
PORT_PLAYER_SLOT_COUNT = 4
KEYBIND_UNBOUND_CODE = 0x17E
DEFAULT_PICK_PERK_CODE = 0x101
DEFAULT_RELOAD_CODE = 0x102
RESERVED_KEYBIND_SLOT_COUNT = 2
PADDING_KEYBIND_SLOT_COUNT = 3

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
    "sound_disabled" / Byte,
    "music_disabled" / Byte,
    "highscore_date_mode" / Byte,
    "highscore_duplicate_mode" / Byte,
    "direction_arrow_flags" / Array(CONFIG_PLAYER_SLOT_COUNT, Byte),
    "shadows_enabled" / Byte,
    "sharp_ground_enabled" / Byte,
    "flame_glow_enabled" / Byte,
    "smoke_enabled" / Byte,
    "padding_12" / Bytes(2),
    "player_count" / Int32sl,
    "game_mode" / Int32sl,
    "movement_schemes" / Array(CONFIG_PLAYER_SLOT_COUNT, Int32sl),
    "aim_schemes" / Array(CONFIG_PLAYER_SLOT_COUNT, Int32sl),
    "config_for" / Int32sl,
    "texture_scale" / Float32l,
    "player_name_buf" / Bytes(12),
    "selected_saved_name_slot" / Int32sl,
    "saved_name_count" / Int32sl,
    "saved_name_order" / Array(SAVED_NAME_SLOT_COUNT, Int32sl),
    "saved_names" / Bytes(SAVED_NAMES_BLOB_SIZE),
    "player_name" / Bytes(PLAYER_NAME_SIZE),
    "player_name_len" / Int32sl,
    "reserved_1a4" / Int32sl,
    "reserved_1a8" / Int32sl,
    "reserved_1ac" / Int32sl,
    "aim_pov_right" / Int32sl,
    "aim_pov_left" / Int32sl,
    "screen_bpp" / Int32sl,
    "screen_width" / Int32sl,
    "screen_height" / Int32sl,
    "windowed_flag" / Byte,
    "windowed_padding" / Bytes(3),
    "input_config" / Array(CONFIG_PLAYER_SLOT_COUNT, PLAYER_BIND_BLOCK_STRUCT),
    "hardcore_flag" / Byte,
    "ui_info_texts" / Byte,
    "hardcore_info_padding" / Bytes(2),
    "level_up_count" / Int32sl,
    "ten_tons_logging_completed" / Int32sl,
    "unique_id_1" / Int32sl,
    "unique_id_2" / Int32sl,
    "reserved_identity_word" / Int32sl,
    "sound_freq_adjustment_enabled" / Byte,
    "sound_frequency_padding" / Bytes(3),
    "sfx_volume" / Float32l,
    "music_volume" / Float32l,
    "violence_disabled" / Byte,
    "show_online_scores" / Byte,
    "safe_mode_backend_enabled" / Byte,
    "detail_padding" / Byte,
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
    shadows_enabled: bool
    flame_glow_enabled: bool
    smoke_enabled: bool
    violence_disabled: int


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
    # Native counts level-ups and turns the info texts off after 50.
    level_up_count: int = 0


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

    @property
    def named_score_list(self) -> str:
        """The selected score list's name; slot 0 is the default list, stored without a name suffix."""
        return self.saved_names[self.selected_saved_name_slot] if self.selected_saved_name_slot else ""

    def add_saved_name(self, name: str) -> None:
        """`ui_profile_menu_update`'s Add: append and select the list; a full set (8) overwrites slot 1 instead.

        Native leaves the selection on the dropped eighth slot there; the port selects the overwritten slot 1.
        Path separators are dropped since the name becomes part of a file name.
        """
        name = name.replace("/", "").replace("\\", "")
        names = list(self.saved_names)
        names[self.saved_name_count] = name
        self.selected_saved_name_slot = self.saved_name_count
        self.saved_name_count += 1
        if self.saved_name_count >= SAVED_NAME_SLOT_COUNT:
            names[1] = name
            self.saved_name_count -= 1
            self.selected_saved_name_slot = 1
        self.saved_names = cast("tuple[str, str, str, str, str, str, str, str]", tuple(names))

    def delete_selected_saved_name(self) -> None:
        """`ui_profile_menu_update`'s Delete: the last list moves into the deleted slot, and the default is selected."""
        names = list(self.saved_names)
        self.saved_name_count -= 1
        names[self.selected_saved_name_slot] = names[self.saved_name_count]
        self.selected_saved_name_slot = 0
        self.saved_names = cast("tuple[str, str, str, str, str, str, str, str]", tuple(names))

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
    # The file's bytes; saving overlays the fields above, so the rest (unparsed flags, ids, bind slots 4-9) survives.
    wire: bytes = msgspec.field(default_factory=lambda: _DEFAULT_WIRE)

    def save(self) -> None:
        atomic_write_bytes(self.path, encode_crimson_cfg(self))


def _player_index(player_index: int) -> int:
    idx = int(player_index)
    if idx < 0 or idx >= 4:
        raise IndexError(f"player index must be in 0..3, got {idx}")
    return idx


def _require_range(value: int, *, minimum: int, maximum: int, field: str) -> int:
    if value < minimum or value > maximum:
        raise ValueError(f"{field} must be in {minimum}..{maximum}, got {value}")
    return value


def _flag(value: object) -> int:
    return 1 if value else 0


def _decode_movement(value: int) -> MovementControlType:
    raw = int(value)
    if raw == 0:
        return MovementControlType.STATIC
    return MovementControlType(raw)


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


# A player bind block's codes by `CrimsonPlayerControls` attribute, in native order.
_BIND_BLOCK_CODES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("move_codes", ("move_forward", "move_backward", "turn_left", "turn_right")),
    ("fire_code", ("fire",)),
    ("keyboard_aim_codes", ("aim_left", "aim_right")),
    ("aim_axis_codes", ("axis_aim_y", "axis_aim_x")),
    ("move_axis_codes", ("axis_move_y", "axis_move_x")),
)


def _decode_bind_block(block: dict[str, Any]) -> dict[str, Any]:
    if not any(block["reserved_keys"]) and not any(block[name] for _, names in _BIND_BLOCK_CODES for name in names):
        # A zeroed block (a slot native never filled) keeps the default binds.
        return {}
    attrs: dict[str, Any] = {}
    for attr, names in _BIND_BLOCK_CODES:
        codes = tuple(block[name] for name in names)
        attrs[attr] = codes if len(codes) > 1 else codes[0]
    return attrs


def _encode_bind_block(player: CrimsonPlayerControls) -> dict[str, object]:
    block: dict[str, object] = {
        "reserved_keys": [KEYBIND_UNBOUND_CODE] * RESERVED_KEYBIND_SLOT_COUNT,
        "padding": [KEYBIND_UNBOUND_CODE] * PADDING_KEYBIND_SLOT_COUNT,
    }
    for attr, names in _BIND_BLOCK_CODES:
        codes = getattr(player, attr)
        block.update(zip(names, codes if len(names) > 1 else (codes,), strict=True))
    return block


class _Field(NamedTuple):
    """A `CRIMSON_CFG_STRUCT` field and the `CrimsonConfig` attribute (`section.attr`) it holds.

    `players.*` targets are per-player slot arrays, of which the port keeps the first four; a bare `players` target
    converts a whole player's bind block.
    """

    wire: str
    target: str
    decode: Callable[[Any], Any] = int
    encode: Callable[[Any], Any] = int
    bounds: tuple[int, int] | None = None

    def checked(self, value: Any) -> Any:
        if self.bounds is not None:
            _require_range(int(value), minimum=self.bounds[0], maximum=self.bounds[1], field=self.wire)
        return value


# Everything the port reads and writes, in native order; the other fields ride along in `CrimsonConfig.wire`.
_CFG_FIELDS: tuple[_Field, ...] = (
    _Field("sound_disabled", "audio.sound_disabled", bool, _flag),
    _Field("music_disabled", "audio.music_disabled", bool, _flag),
    _Field("highscore_date_mode", "profile.score_date_mode", HighScoreDateMode),
    _Field("direction_arrow_flags", "players.show_direction_arrow", bool, _flag),
    _Field("shadows_enabled", "display.shadows_enabled", bool, _flag),
    _Field("flame_glow_enabled", "display.flame_glow_enabled", bool, _flag),
    _Field("smoke_enabled", "display.smoke_enabled", bool, _flag),
    _Field("player_count", "gameplay.player_count", bounds=(1, 4)),
    _Field("game_mode", "gameplay.mode", GameMode),
    _Field("movement_schemes", "players.movement", _decode_movement),
    _Field("aim_schemes", "players.aim_scheme", AimScheme),
    _Field("texture_scale", "display.texture_scale", float, float),
    _Field("selected_saved_name_slot", "profile.selected_saved_name_slot", bounds=(0, SAVED_NAME_SLOT_COUNT - 1)),
    _Field("saved_name_count", "profile.saved_name_count", bounds=(1, SAVED_NAME_SLOT_COUNT)),
    _Field("saved_names", "profile.saved_names", _decode_saved_names, _encode_saved_names_blob),
    _Field("player_name", "profile.player_name", _decode_player_name, _encode_player_name_buffer),
    _Field("player_name_len", "profile.player_name_input_len", bounds=(0, PLAYER_NAME_MAX_BYTES)),
    _Field("screen_bpp", "display.bpp"),
    _Field("screen_width", "display.width"),
    _Field("screen_height", "display.height"),
    _Field("windowed_flag", "display.windowed", bool, _flag),
    _Field("input_config", "players", _decode_bind_block, _encode_bind_block),
    _Field("hardcore_flag", "gameplay.hardcore", bool, _flag),
    _Field("ui_info_texts", "gameplay.show_info_texts", bool, _flag),
    _Field("level_up_count", "gameplay.level_up_count"),
    _Field("sfx_volume", "audio.sfx_volume", float, float),
    _Field("music_volume", "audio.music_volume", float, float),
    _Field("violence_disabled", "display.violence_disabled"),
    _Field("show_online_scores", "profile.show_internet_scores", bool, _flag),
    _Field("detail_preset", "display.detail_preset", bounds=(1, 5)),
    _Field("mouse_sensitivity", "display.mouse_sensitivity", float, float),
    _Field("keybind_pick_perk", "controls.pick_perk_code"),
    _Field("keybind_reload", "controls.reload_code"),
)


def default_player_controls(player_index: int) -> CrimsonPlayerControls:
    # A fresh copy: callers rebind its fields.
    return msgspec.structs.replace(_DEFAULT_PLAYER_CONTROL_TEMPLATES[_player_index(player_index)])


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
            shadows_enabled=True,
            flame_glow_enabled=True,
            smoke_enabled=True,
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
                default_player_controls(0),
                default_player_controls(1),
                default_player_controls(2),
                default_player_controls(3),
            ),
            pick_perk_code=DEFAULT_PICK_PERK_CODE,
            reload_code=DEFAULT_RELOAD_CODE,
        ),
    )


# Port 0.10.0 kept the P3/P4 direction arrows in two bytes at the front of bind slot 4 (1 off, 2 on), which native
# leaves zeroed, and wrote native's own P3/P4 flags as 0.
_DIRECTION_ARROW_FLAGS_OFFSET = 0x04
_BIND_SLOT_4_OFFSET = 0x1C8 + 4 * PLAYER_BIND_BLOCK_SIZE
_LEGACY_ARROW_OFF = 1
_LEGACY_ARROW_ON = 2


def _migrate_legacy_p3_p4_arrows(blob: bytes) -> bytes:
    """Move port 0.10.0's P3/P4 direction arrows into native's flags; anything else passes through unchanged."""

    legacy = blob[_BIND_SLOT_4_OFFSET : _BIND_SLOT_4_OFFSET + 2]
    rest = blob[_BIND_SLOT_4_OFFSET + 2 : _BIND_SLOT_4_OFFSET + PLAYER_BIND_BLOCK_SIZE]
    if any(flag not in (_LEGACY_ARROW_OFF, _LEGACY_ARROW_ON) for flag in legacy) or any(rest):
        return blob
    migrated = bytearray(blob)
    for player_index, flag in enumerate(legacy, start=2):
        migrated[_DIRECTION_ARROW_FLAGS_OFFSET + player_index] = int(flag == _LEGACY_ARROW_ON)
    migrated[_BIND_SLOT_4_OFFSET : _BIND_SLOT_4_OFFSET + 2] = bytes(2)
    return bytes(migrated)


def decode_crimson_cfg(path: Path, blob: bytes) -> CrimsonConfig:
    if len(blob) != CRIMSON_CFG_SIZE:
        raise ValueError(f"{path} has unexpected size {len(blob)} (expected {CRIMSON_CFG_SIZE})")
    blob = _migrate_legacy_p3_p4_arrows(blob)
    raw = CRIMSON_CFG_STRUCT.parse(blob)
    if raw["detail_preset"] == 0 and not (raw["shadows_enabled"] or raw["flame_glow_enabled"] or raw["smoke_enabled"]):
        # No detail settings at all loads as full detail.
        raw["detail_preset"] = 5
        raw["shadows_enabled"] = raw["flame_glow_enabled"] = raw["smoke_enabled"] = 1

    sections: defaultdict[str, dict[str, Any]] = defaultdict(dict)
    players: list[dict[str, Any]] = [{} for _ in range(PORT_PLAYER_SLOT_COUNT)]
    for field in _CFG_FIELDS:
        section, _, attr = field.target.partition(".")
        if section == "players":
            for player, value in zip(players, raw[field.wire], strict=False):
                decoded = field.decode(value)
                player.update({attr: decoded} if attr else decoded)
        else:
            sections[section][attr] = field.decode(field.checked(raw[field.wire]))
    return CrimsonConfig(
        path=path,
        display=CrimsonDisplayConfig(**sections["display"]),
        audio=CrimsonAudioConfig(**sections["audio"]),
        gameplay=CrimsonGameplayConfig(quest_level=None, **sections["gameplay"]),
        profile=CrimsonProfileConfig(**sections["profile"]),
        controls=CrimsonControlsConfig(
            players=cast(
                "tuple[CrimsonPlayerControls, CrimsonPlayerControls, CrimsonPlayerControls, CrimsonPlayerControls]",
                tuple(
                    msgspec.structs.replace(template, **player)
                    for template, player in zip(_DEFAULT_PLAYER_CONTROL_TEMPLATES, players, strict=True)
                ),
            ),
            **sections["controls"],
        ),
        wire=bytes(blob),
    )


def _default_wire() -> bytes:
    """A fresh crimson.cfg: zeroes plus the constants native writes."""
    data = dict(CRIMSON_CFG_STRUCT.parse(bytes(CRIMSON_CFG_SIZE)))
    data["reserved_1a4"] = 100
    data["aim_pov_right"] = 9000
    data["aim_pov_left"] = 27000
    data["ten_tons_logging_completed"] = 1
    data["sound_freq_adjustment_enabled"] = 1
    return CRIMSON_CFG_STRUCT.build(data)


_DEFAULT_WIRE = _default_wire()


def encode_crimson_cfg(config: CrimsonConfig) -> bytes:
    data = dict(CRIMSON_CFG_STRUCT.parse(config.wire))
    for field in _CFG_FIELDS:
        section, _, attr = field.target.partition(".")
        if section == "players":
            for idx, player in enumerate(config.controls.players):
                data[field.wire][idx] = field.encode(getattr(player, attr) if attr else player)
        else:
            data[field.wire] = field.encode(field.checked(getattr(getattr(config, section), attr)))
    # The port keeps the named score lists in slot order.
    data["saved_name_order"] = list(range(SAVED_NAME_SLOT_COUNT))
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
    # Native `config_apply_detail_preset`: preset 1 turns smoke off and falls through to 2, which leaves it alone.
    if selected == 1:
        config.display.smoke_enabled = False
    if selected <= 2:
        config.display.shadows_enabled = False
        config.display.flame_glow_enabled = False
    else:
        config.display.shadows_enabled = True
        config.display.flame_glow_enabled = True
        config.display.smoke_enabled = True
    return selected
